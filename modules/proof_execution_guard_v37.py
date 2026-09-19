#!/usr/bin/env python3
"""V37 execution guard for controlled proof adapters.

The guard is deliberately small: it limits requests/body size, refuses redirects,
checks every destination against the engagement allowlist, and records request
metadata. It does not provide arbitrary command execution or payload execution.
"""
from __future__ import annotations
import urllib.error, urllib.request
from dataclasses import dataclass, asdict
from urllib.parse import urlsplit
from modules.scope import is_in_scope

@dataclass
class ExecutionGuard:
    allowed_hosts: list[str]
    max_requests: int = 3
    max_body_bytes: int = 64 * 1024
    requests_used: int = 0
    events: list[dict] | None = None

    def __post_init__(self):
        if self.events is None:
            self.events = []
        if not self.allowed_hosts:
            raise ValueError("Execution guard requires a non-empty scope allowlist")
        if self.max_requests < 1 or self.max_requests > 3:
            raise ValueError("max_requests must be 1..3")
        if self.max_body_bytes < 1024 or self.max_body_bytes > 64 * 1024:
            raise ValueError("invalid body limit")

    def _check_url(self, url: str):
        p = urlsplit(url)
        if p.scheme.lower() not in {"http", "https"} or not p.hostname:
            raise PermissionError("Only HTTP(S) URLs with a hostname are permitted")
        if not is_in_scope(p.hostname.lower(), self.allowed_hosts):
            raise PermissionError("Request destination is outside approved scope")

    def request(self, url: str, method: str = "GET", headers: dict | None = None, timeout: int = 8):
        self._check_url(url)
        if self.requests_used >= self.max_requests:
            raise RuntimeError("Proof request budget exhausted")
        self.requests_used += 1
        req = urllib.request.Request(url, method=method, headers=headers or {})
        # Explicitly disable redirect following. This is important for proof-only checks.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        opener = urllib.request.build_opener(NoRedirect)
        try:
            with opener.open(req, timeout=timeout) as r:
                body = r.read(self.max_body_bytes)
                result = {"ok": True, "status": r.status, "headers": dict(r.headers),
                          "body": body.decode("utf-8", "replace"), "final_url": r.geturl()}
        except urllib.error.HTTPError as e:
            body = e.read(self.max_body_bytes).decode("utf-8", "replace")
            result = {"ok": False, "status": e.code, "headers": dict(e.headers),
                      "body": body, "final_url": url, "error": str(e)}
        except Exception as e:
            result = {"ok": False, "status": None, "headers": {}, "body": "",
                      "final_url": url, "error": str(e)}
        self.events.append({"method": method, "url": url, "status": result.get("status"),
                            "body_bytes_observed": len(result.get("body", "").encode("utf-8")),
                            "redirects_followed": False})
        return result

    def snapshot(self):
        return {"limits": {"max_requests": self.max_requests, "max_body_bytes": self.max_body_bytes},
                "requests_used": self.requests_used, "events": list(self.events or [])}
