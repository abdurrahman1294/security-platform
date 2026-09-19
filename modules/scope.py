#!/usr/bin/env python3
"""Fail-closed engagement scope validation."""

import ipaddress
import re
from urllib.parse import urlparse
from pathlib import Path

from modules.security import in_scope

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$")
HOST_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def load_scope(scope_file: str) -> list[str]:
    path = Path(scope_file)
    if not path.exists() or not path.is_file():
        return []
    return [line.strip().lower() for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")]


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_valid_target_format(target: str) -> bool:
    if not isinstance(target, str) or not target or len(target) > 2048:
        return False
    if re.search(r"[;&|`$(){}<>\\\"\'\n\r]", target):
        return False
    # Accept a website URL as an assessment target, but never allow
    # credentials, fragments, or non-HTTP schemes. Scope matching is performed
    # against the parsed hostname by modules.security.in_scope().
    if target.startswith(("http://", "https://")):
        try:
            parsed = urlparse(target)
            if parsed.username or parsed.password or parsed.fragment or not parsed.hostname:
                return False
            host = parsed.hostname.rstrip(".")
            if "%" in host:
                return False
            if not (DOMAIN_RE.match(host) or HOST_RE.match(host) or IPV4_RE.match(host) or _is_ip(host)):
                return False
            if parsed.port is not None and not (1 <= parsed.port <= 65535):
                return False
            return True
        except ValueError:
            return False
    if DOMAIN_RE.match(target) or HOST_RE.match(target):
        return True
    if IPV4_RE.match(target) or _is_ip(target):
        return True
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        return False


def is_in_scope(asset: str, allowed: list[str]) -> bool:
    return in_scope(asset, allowed)


def validate_target_or_exit(target: str, scope_file: str = None):
    if not is_valid_target_format(target):
        raise SystemExit(f"Invalid or dangerous target format: {target}")
    if not scope_file:
        raise SystemExit("A scope allowlist is required for active testing.")
    allowed = load_scope(scope_file)
    if not allowed:
        raise SystemExit(f"Scope file '{scope_file}' is missing or empty; refusing to run.")
    if not is_in_scope(target, allowed):
        raise SystemExit(f"Target '{target}' is OUT OF SCOPE according to '{scope_file}'.")
    return True


def filter_in_scope(assets: list[str], scope_file: str = None, allowed: list[str] | None = None) -> list[str]:
    if allowed is None:
        if not scope_file:
            return []
        allowed = load_scope(scope_file)
    if not allowed:
        return []
    return [asset for asset in assets if is_in_scope(asset, allowed)]
