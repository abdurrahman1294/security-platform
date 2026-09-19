"""Safe, evidence-driven vulnerability validation for the disposable local lab.

Only bounded, non-destructive proof checks are implemented. The module refuses
non-loopback targets and never executes arbitrary commands or payloads.
"""
from __future__ import annotations
import json, time, urllib.parse
from pathlib import Path
from typing import Any
from modules.atomic_io import atomic_write_json
from modules.lab_http import base as _lab_base, request as _lab_request

LOOPBACK = {"127.0.0.1", "localhost", "::1"}
TECHNIQUES = {
    "xss_reflection": ("/search?q=SPV21-XSS-MARKER", "SPV21-XSS-MARKER"),
    "sqli_boolean": ("/api/v1/product?id=1%20OR%201%3D1", '"rows"'),
    "idor": ("/user?id=2", '"username":"admin"'),
    "path_traversal": ("/download?file=../app/lab-secrets/app.env", "LAB_DB_USER="),
    "open_redirect": ("/api/v1/redirect?url=/lab/objective", "Location"),
    "config_exposure": ("/api/v1/admin/config", "training_secret"),
    "session_cookie_flags": ("/login", "lab_session"),
}

def _base(target: str) -> str:
    return _lab_base(target)

def _request(url: str, method: str = "GET", body: bytes | None = None, headers: dict[str, str] | None = None) -> dict[str, Any]:
    return _lab_request(url, method=method, data=body, headers=headers)


def validate(root: str | Path, target: str, techniques: list[str] | tuple[str, ...] | None = None) -> dict[str, Any]:
    base = _base(target)
    selected = list(techniques or TECHNIQUES)
    unknown = [x for x in selected if x not in TECHNIQUES]
    if unknown:
        raise ValueError(f"unknown lab validation techniques: {unknown}")
    results = []
    for technique in selected:
        path, marker = TECHNIQUES[technique]
        if technique == "session_cookie_flags":
            form = urllib.parse.urlencode({"username": "alice", "password": "alice123"}).encode()
            r = _request(base + path, method="POST", body=form, headers={"Content-Type":"application/x-www-form-urlencoded"})
        else:
            r = _request(base + path)
        body = r.get("body", "")
        headers = {str(k).lower(): str(v) for k, v in r.get("headers", {}).items()}
        if technique == "open_redirect":
            found = "location" in headers and "/lab/objective" in headers["location"]
        elif technique == "session_cookie_flags":
            cookie = headers.get("set-cookie", "")
            found = "lab_session=" in cookie and not all(flag in cookie.lower() for flag in ("httponly", "secure", "samesite="))
        else:
            found = marker.lower() in body.lower()
        results.append({"technique": technique, "status": "CONFIRMED" if found else "NOT_CONFIRMED",
                        "http_status": r.get("http_status"), "evidence_marker": marker,
                        "path": path, "ts": time.time()})
    out = {"schema_version": "22.0", "target": base, "lab_only": True, "results": results,
           "confirmed": sum(x["status"] == "CONFIRMED" for x in results)}
    ev = Path(root) / "evidence"; ev.mkdir(parents=True, exist_ok=True)
    atomic_write_json(ev / "controlled-validation-v21.json", out)
    return out
