#!/usr/bin/env python3
"""Central safety helpers for authorized engagement execution."""

import getpass
import ipaddress
import re
from urllib.parse import urlparse

AUTH_PHRASE = "I HAVE AUTHORIZATION"
CLIENT_RE = re.compile(r"[^A-Za-z0-9._-]+")
SECRET_KEYS = {
    "authorization", "cookie", "set-cookie", "token", "access_token", "refresh_token",
    "jwt", "password", "passwd", "secret", "api_key", "apikey", "client_secret",
    "private_key", "access_key", "session_id", "authorization_code", "credentials"
}


def safe_client_name(value: str) -> str:
    value = CLIENT_RE.sub("-", (value or "").strip()).strip(".-_")
    return (value or "client")[:80]


def require_authorization() -> None:
    """Require an explicit interactive confirmation before active testing."""
    print("\n" + "=" * 72)
    print(" AUTHORIZATION GATE")
    print("=" * 72)
    print("Active testing is about to begin. Confirm that you have explicit written")
    print("permission and that the target is within the engagement scope.")
    print(f"Type exactly: {AUTH_PHRASE}")
    print("=" * 72)
    try:
        answer = getpass.getpass("Authorization phrase → ").strip()
    except (EOFError, KeyboardInterrupt):
        raise SystemExit("Authorization not confirmed; aborting.")
    if answer != AUTH_PHRASE:
        raise SystemExit("Authorization not confirmed; aborting before any active scan.")


def redact_text(value: str) -> str:
    if not value:
        return value
    value = re.sub(r"(?i)(authorization\s*:\s*bearer\s+)[^\s,;]+", r"\1[REDACTED]", value)
    value = re.sub(r"(?i)(cookie\s*:\s*)[^\r\n]+", r"\1[REDACTED]", value)
    value = re.sub(r"(?i)(password|passwd|secret|token|api[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token)\s*[=:]\s*[^\s,;&]+", r"\1=[REDACTED]", value)
    value = re.sub(r"(?i)([?&](?:password|passwd|secret|token|api[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token)=)[^&\s]+", r"\1[REDACTED]", value)
    return value


def redact_mapping(data):
    if isinstance(data, dict):
        return {
            k: ("[REDACTED]" if str(k).lower().replace("-", "_") in SECRET_KEYS else redact_mapping(v))
            for k, v in data.items()
        }
    if isinstance(data, list):
        return [redact_mapping(v) for v in data]
    if isinstance(data, str):
        return redact_text(data)
    return data


def _normalise_asset(asset: str) -> str:
    asset = (asset or "").strip().lower()
    if asset.startswith(("http://", "https://")):
        try:
            parsed = urlparse(asset)
            asset = parsed.hostname or ""
        except ValueError:
            return ""
    else:
        asset = re.sub(r"^https?://", "", asset)
    asset = asset.split("/", 1)[0]
    if asset.startswith("[") and "]" in asset:
        return asset[1:].split("]", 1)[0]
    if asset.count(":") == 1:
        asset = asset.rsplit(":", 1)[0]
    return asset.rstrip(".")


def in_scope(asset: str, allowed: list[str]) -> bool:
    host = _normalise_asset(asset)
    if not host or not allowed:
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None

    for raw in allowed:
        entry = raw.strip().lower()
        if not entry or entry.startswith("#"):
            continue
        if entry.startswith("*."):
            suffix = entry[1:]
            if host == entry[2:] or host.endswith(suffix):
                return True
            continue
        try:
            network = ipaddress.ip_network(entry, strict=False)
            if ip is not None and ip in network:
                return True
            continue
        except ValueError:
            pass
        if host == entry.rstrip("."):
            return True
    return False
