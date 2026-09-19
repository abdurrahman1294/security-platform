"""Strict loopback HTTP helpers for disposable lab proof adapters."""
from __future__ import annotations
import json, urllib.error, urllib.parse, urllib.request

LOOPBACK = {"127.0.0.1", "localhost", "::1"}
MAX_BODY = 65536
TIMEOUT = 5

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

OPENER = urllib.request.build_opener(_NoRedirect())

def _parse(url: str):
    if not isinstance(url, str) or len(url) > 2048:
        raise ValueError("invalid lab URL")
    p = urllib.parse.urlsplit(url if "://" in url else "http://" + url)
    if p.scheme not in {"http", "https"} or p.hostname not in LOOPBACK:
        raise ValueError("lab adapter is loopback-only")
    if p.username or p.password or p.fragment:
        raise ValueError("lab URL must not contain credentials or fragment")
    try: port = p.port
    except ValueError as exc: raise ValueError("invalid port") from exc
    if port is None: port = 443 if p.scheme == "https" else 80
    if not (1 <= port <= 65535): raise ValueError("invalid port")
    return p, port

def base(url: str) -> str:
    p, port = _parse(url)
    if p.query or p.path not in ("", "/"):
        raise ValueError("lab target base must not contain path or query")
    return f"{p.scheme}://{p.hostname}:{port}"

def request(url: str, method="GET", headers=None, data=None, timeout=TIMEOUT, max_body=MAX_BODY):
    p, port = _parse(url)
    u = f"{p.scheme}://{p.hostname}:{port}{p.path or '/'}"
    if p.query: u += "?" + p.query
    method = str(method).upper()
    if method not in {"GET", "HEAD", "OPTIONS", "POST"}:
        return {"ok": False, "status": None, "headers": {}, "body": "", "url": u, "error": "method-not-allowed"}
    if data is not None and not isinstance(data, (bytes, bytearray)):
        data = json.dumps(data).encode()
    try:
        timeout = max(1, min(int(timeout), 30)); max_body = max(0, min(int(max_body), 1024 * 1024))
    except (TypeError, ValueError):
        return {"ok": False, "status": None, "headers": {}, "body": "", "url": u, "error": "invalid-limits"}
    hdrs = {"User-Agent": "SecurityPlatform-V22-Lab", **(headers or {})}
    req = urllib.request.Request(u, data=data, method=method, headers=hdrs)
    try:
        with OPENER.open(req, timeout=timeout) as r:
            return {"ok": True, "status": r.status, "headers": dict(r.headers), "body": r.read(max_body).decode("utf-8", "replace"), "url": u}
    except urllib.error.HTTPError as e:
        body = e.read(max_body).decode("utf-8", "replace") if e.fp else ""
        return {"ok": True, "status": e.code, "headers": dict(e.headers or {}), "body": body, "url": u}
    except Exception as e:
        return {"ok": False, "status": None, "headers": {}, "body": "", "url": u, "error": type(e).__name__}
