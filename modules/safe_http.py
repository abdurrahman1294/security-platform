#!/usr/bin/env python3
"""Shared bounded HTTP request helper for controlled observation/validation code.

Several modules (controlled_validation, controlled_exploitation_v30,
web_probe_v49) scope-check a URL and then issue a request, but previously
did so with the *default* urllib opener -- which transparently follows
HTTP redirects (301/302/303/307/308). A scope check performed only on the
original URL is worthless if the request silently follows a redirect
Location header to a host that was never checked: the framework would then
make a live network request to an address the operator never authorized,
while still reporting the pre-redirect URL as "observed" and "scope
checked".

This module centralizes a single request path that:
  - never follows redirects (a 3xx response is returned as-is, with the
    Location header surfaced to the caller so it can be logged/reported,
    not silently chased)
  - enforces a response-size cap
  - enforces a timeout

Every module that performs a bounded HTTP observation/validation request
against a scope-checked target should go through here instead of rolling
its own urlopen() call, exactly for the same reason modules/findings_io.py
centralizes finding-file parsing: format/behavior drift when the logic is
duplicated is how these gaps happen in the first place.
"""
from __future__ import annotations

import urllib.error
import urllib.request
from urllib.parse import urlparse

MAX_BODY_DEFAULT = 65536
DEFAULT_TIMEOUT = 10


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirect())


def request(
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    max_body: int = MAX_BODY_DEFAULT,
) -> dict:
    """Issue one bounded, non-redirect-following HTTP request.

    Always returns a dict describing what happened; never raises for
    ordinary HTTP-level outcomes (4xx/5xx/3xx are all "ok": True with the
    status code surfaced). Only transport-level failures (DNS, connection
    refused, timeout, TLS errors, ...) come back as "ok": False.

    A 3xx response is returned exactly as received -- it is NOT followed.
    Callers that care where a redirect points to should inspect
    result["headers"].get("Location") and, if they want to look at the
    target, run it back through their own scope check and issue a new
    call to this function -- never assume it's safe to fetch.
    """
    if not isinstance(url, str) or len(url) > 2048:
        return {"ok": False, "status": None, "headers": {}, "body": "", "final_url": str(url), "redirects_followed": False, "error": "invalid-url"}
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        return {"ok": False, "status": None, "headers": {}, "body": "", "final_url": url, "redirects_followed": False, "error": "invalid-url"}
    method = str(method).upper().strip()
    if method not in {"GET", "HEAD", "OPTIONS"}:
        return {"ok": False, "status": None, "headers": {}, "body": "", "final_url": url, "redirects_followed": False, "error": "method-not-allowed"}
    try:
        timeout = max(1, min(int(timeout), 30))
        max_body = max(0, min(int(max_body), 1024 * 1024))
    except (TypeError, ValueError):
        return {"ok": False, "status": None, "headers": {}, "body": "", "final_url": url, "redirects_followed": False, "error": "invalid-limits"}
    req = urllib.request.Request(url, method=method, headers=headers or {})
    try:
        with _NO_REDIRECT_OPENER.open(req, timeout=timeout) as resp:
            body = resp.read(max_body)
            hdrs = dict(resp.headers)
            return {
                "ok": True,
                "status": resp.status,
                "headers": hdrs,
                "body": body.decode("utf-8", "replace"),
                "final_url": resp.geturl(),
                "redirects_followed": False,
            }
    except urllib.error.HTTPError as exc:
        # HTTPError also fires for the 3xx codes our NoRedirect handler
        # declines to follow -- these are still a normal, successful
        # observation of "the server said redirect to X", not a failure.
        body = b""
        try:
            body = exc.read(max_body)
        except (OSError, ValueError):
            pass
        hdrs = dict(exc.headers) if exc.headers else {}
        return {
            "ok": True,
            "status": exc.code,
            "headers": hdrs,
            "body": body.decode("utf-8", "replace"),
            "final_url": url,
            "redirects_followed": False,
            "location": hdrs.get("Location", ""),
        }
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        return {
            "ok": False,
            "status": None,
            "headers": {},
            "body": "",
            "final_url": url,
            "redirects_followed": False,
            "error": type(exc).__name__,
            "detail": str(exc)[:200],
        }
