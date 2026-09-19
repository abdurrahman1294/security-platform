"""Credential discovery and controlled verification for authorized engagements.

The discovery side is artifact/content based and records exact provenance. Raw
secrets are kept in evidence/credentials.json (0600) and are never copied into
normal findings or reports. Verification is deliberately narrow: the built-in
HTTP verifier is available only for loopback/local lab targets and must be
explicitly requested by the operator.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from modules.credentials import load_creds, save_creds

_SECRET_PATTERNS = [
    re.compile(r"(?im)^\s*(?:LAB_)?(?:DB_)?(?:PASSWORD|PASS|SECRET|TOKEN|API_KEY)\s*=\s*['\"]?([^'\"\s#]+)"),
    re.compile(r"(?im)\b(?:password|passwd|secret|token|api[_-]?key)\s*[:=]\s*['\"]([^'\"]{3,256})['\"]"),
]
_USER_PATTERNS = [
    re.compile(r"(?im)^\s*(?:LAB_)?(?:DB_)?(?:USER(?:NAME)?|USERNAME)\s*=\s*['\"]?([^'\"\s#]+)"),
    re.compile(r"(?im)\b(?:username|user)\s*[:=]\s*['\"]([^'\"]{2,128})['\"]"),
]
_COMBINED = re.compile(r"(?im)(?:username|user)\s*[:=]\s*['\"]([^'\"]+)['\"].{0,180}?(?:password|passwd|secret)\s*[:=]\s*['\"]([^'\"]+)['\"]")


def _loopback(host: str) -> bool:
    raw = (host or "").strip()
    if "://" in raw:
        raw = urllib.parse.urlsplit(raw).hostname or ""
    else:
        raw = raw.split(":", 1)[0]
    h = raw.strip("[]").lower()
    return h in {"127.0.0.1", "localhost", "::1"}


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8", "replace")).hexdigest()


def _safe_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for p in root.rglob("*"):
        if not p.is_file() or "credentials.json" in p.name:
            continue
        try:
            if p.stat().st_size > 1024 * 1024:
                continue
        except OSError:
            continue
        if p.suffix.lower() in {".txt", ".env", ".bak", ".conf", ".cfg", ".ini", ".json", ".js", ".html", ".xml", ".yaml", ".yml", ".log", ".md"}:
            files.append(p)
    return files


DEFAULT_WEB_PATHS = (
    "/.env", "/.env.bak", "/backup/.env", "/backups/app.env.bak",
    "/config/.env", "/config.json", "/static/js/app.js",
    "/lab-secrets/app.env", "/download?file=../../app/lab-secrets/app.env",
    "/download?file=../../app/backups/app.env.bak",
)

def discover_web_content(outdir: str | Path, base_url: str, paths: tuple[str, ...] = DEFAULT_WEB_PATHS) -> dict[str, Any]:
    """GET bounded candidate public files and feed their bodies into discovery.

    Only HTTP(S) URLs on loopback targets are probed by this convenience lab
    adapter. Every request is a single GET with a small response cap and no
    redirects. It is intentionally not a directory brute-forcer.
    """
    from modules.safe_http import request
    parsed = urllib.parse.urlsplit(base_url if base_url.startswith("http") else "http://" + base_url)
    if parsed.scheme not in {"http", "https"} or not _loopback(parsed.hostname or ""):
        return {"status": "blocked", "reason": "credential-content-probe-is-loopback-only", "fetched": 0}
    root = Path(outdir) / "evidence" / "credential-content"
    root.mkdir(parents=True, exist_ok=True)
    fetched = 0
    for raw in paths:
        if not raw.startswith("/"):
            continue
        # Query parameters are allowed for fixed lab fixtures, but path traversal
        # is never constructed by the adapter itself; paths are predeclared above.
        url = f"{parsed.scheme}://{parsed.netloc}{raw}"
        obs = request(url, method="GET", timeout=10, max_body=65536)
        if not obs.get("ok") or not obs.get("body"):
            continue
        fetched += 1
        name = hashlib.sha256(raw.encode()).hexdigest()[:16] + ".txt"
        (root / name).write_text(obs["body"], encoding="utf-8")
    result = discover(outdir)
    result.update({"web_probe_status": "completed", "fetched": fetched, "base_url": f"{parsed.scheme}://{parsed.netloc}"})
    return result

def discover(outdir: str | Path) -> dict[str, Any]:
    root = Path(outdir)
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    files = _safe_files(root)
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = str(path.relative_to(root))
        pairs = [(m.group(1), m.group(2), "paired") for m in _COMBINED.finditer(text)]
        for user, secret, method in pairs:
            key = (user, secret, rel)
            if key in seen:
                continue
            seen.add(key)
            candidates.append({"username": user, "secret": secret, "source": rel, "method": method})
        users = [m.group(1) for pat in _USER_PATTERNS for m in pat.finditer(text)]
        secrets = [m.group(1) for pat in _SECRET_PATTERNS for m in pat.finditer(text)]
        for secret in secrets:
            user = users[0] if users else ""
            key = (user, secret, rel)
            if key in seen:
                continue
            seen.add(key)
            candidates.append({"username": user, "secret": secret, "source": rel, "method": "key-value"})

    # Scan existing recon/web artifacts as well as engagement output.
    for c in candidates:
        c["credential_id"] = "cred-" + _hash(c["source"] + "\0" + c["username"] + "\0" + c["secret"])[:12]
        c["secret_sha256"] = _hash(c["secret"])
        c["discovery_status"] = "discovered"
        c["verification_status"] = "unknown"
        c["verification_method"] = "none"

    if candidates:
        existing = load_creds(str(root))
        # Replace same credential IDs so reruns are deterministic.
        by_id = {x.get("credential_id"): x for x in existing if isinstance(x, dict) and x.get("credential_id")}
        for c in candidates:
            by_id[c["credential_id"]] = {
                "credential_id": c["credential_id"],
                "system": c.get("service", "unknown"),
                "username": c["username"],
                "secret": c["secret"],
                "type": "password_or_secret",
                "note": f"discovered from {c['source']}",
                "source": c["source"],
                "secret_sha256": c["secret_sha256"],
                "discovery_status": "discovered",
                "verification_status": "unknown",
                "verification_method": "none",
            }
        save_creds(str(root), list(by_id.values()))

    result = {"schema_version": "19.0", "status": "completed", "count": len(candidates), "credentials": candidates}
    (root / "evidence" / "credential-discovery.json").write_text(json.dumps({
        **result,
        "credentials": [{k: v for k, v in c.items() if k != "secret"} for c in candidates],
    }, indent=2) + "\n", encoding="utf-8")
    return result


def verify_local_lab(outdir: str | Path, target: str, credential_id: str = "") -> dict[str, Any]:
    """Verify one discovered credential against the lab's explicit verifier.

    This adapter is intentionally loopback-only and makes exactly one GET
    request per selected credential. It does not spray credentials.
    """
    root = Path(outdir)
    if not _loopback(target):
        return {"status": "blocked", "reason": "local-lab-verifier-is-loopback-only"}
    creds = load_creds(str(root))
    selected = [c for c in creds if not credential_id or c.get("credential_id") == credential_id]
    if not selected:
        return {"status": "not_found", "count": 0}
    parsed = urllib.parse.urlsplit(target if target.startswith("http") else "http://" + target)
    base = f"{parsed.scheme}://{parsed.netloc}"
    results = []
    for c in selected[:1]:
        q = urllib.parse.urlencode({"username": c.get("username", ""), "password": c.get("secret", "")})
        url = base + "/api/v1/credential-verification?" + q
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = resp.read(65536).decode("utf-8", "replace")
                ok = resp.status == 200 and '"valid":true' in body.replace(" ", "").lower()
                status = "valid" if ok else "invalid"
                method = "local-lab-verifier"
        except Exception as exc:  # transport and HTTP failures are non-fatal evidence
            status = "unknown"
            method = "local-lab-verifier-error"
            body = ""
            err = type(exc).__name__
        c["verification_status"] = status
        c["verification_method"] = method
        c["verified_target"] = target
        results.append({"credential_id": c.get("credential_id"), "username": c.get("username"), "verification_status": status,
                        "verification_method": method, "target": target, "response_observed": bool(body)})
        for stored in creds:
            if stored.get("credential_id") == c.get("credential_id"):
                stored.update({"verification_status": status, "verification_method": method, "verified_target": target})
    save_creds(str(root), creds)
    (root / "evidence" / "credential-verification.json").write_text(json.dumps({"schema_version":"19.0","results":results}, indent=2) + "\n", encoding="utf-8")
    return {"status": "completed", "results": results}
