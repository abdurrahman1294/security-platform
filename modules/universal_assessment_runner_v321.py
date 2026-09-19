"""V3.21 governed universal assessment runner.

Turns the V3.20 universal surface plan into bounded, functional R0-R2
execution. Only already-registered ToolManager adapters are invoked. The
perspective is an assessment origin label: cellular/internet execution is
performed from the machine on that network, never by bypassing carrier,
firewall, NAT, or other access controls.
"""
from __future__ import annotations

import hashlib
import json
import socket
import time
from pathlib import Path
from typing import Any, Iterable

from modules.atomic_io import atomic_write_json
from modules.universal_attack_surface_fabric_v320 import (
    ATTACK_SURFACES,
    EXECUTION_ADAPTERS,
    PERSPECTIVES,
    build_functional_assessment_plan,
)
from modules.scope import load_scope
from modules.security import in_scope
from security_platform.core.tools import run as run_tool

VERSION = "3.21.0"
MAX_STEPS = 24
MAX_TIMEOUT = 900


def _hash(*parts: Any) -> str:
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:16]


def _write(root: str | Path, name: str, data: dict[str, Any]):
    root = Path(root)
    (root / "evidence").mkdir(parents=True, exist_ok=True)
    atomic_write_json(root / "evidence" / name, data)
    return data


def _host(target: str) -> str:
    raw = target.strip()
    if raw.startswith(("http://", "https://")):
        from urllib.parse import urlparse
        return urlparse(raw).hostname or raw
    return raw.split("/", 1)[0].split(":", 1)[0]


def _target_url(target: str) -> str:
    if target.startswith(("http://", "https://")):
        return target
    return "https://" + target


def _safe_slug(value: str) -> str:
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in value)[:80] or "target"


def _adapter_actions(surface: str, target: str, root: Path) -> list[tuple[str, list[str], str]]:
    """Build only fixed, allowlisted R0-R2 command lines."""
    host = _host(target)
    url = _target_url(target)
    ev = root / "evidence"
    slug = _safe_slug(host)
    out: list[tuple[str, list[str], str]] = []

    if surface in {"external_web", "api"}:
        out.append(("httpx", ["httpx", "-u", url, "-silent", "-status-code", "-title", "-tech-detect", "-json", "-o", str(ev / f"v321-httpx-{slug}.jsonl")], "R1_bounded_discovery"))
    elif surface == "dns_certificate":
        out.append(("subfinder", ["subfinder", "-d", host, "-silent", "-o", str(ev / f"v321-subdomains-{slug}.txt")], "R1_bounded_discovery"))
    elif surface == "internet_services":
        out.append(("nmap", ["nmap", "-sV", "-T3", "--open", "-oN", str(ev / f"v321-services-{slug}.txt"), host], "R1_bounded_discovery"))
    elif surface == "remote_access":
        out.append(("nmap", ["nmap", "-sV", "-T3", "--open", "-p", "22,80,443,445,3389,5900,5985,5986", "-oN", str(ev / f"v321-remote-access-{slug}.txt"), host], "R1_bounded_discovery"))
    elif surface == "network_devices":
        out.append(("nmap", ["nmap", "-sV", "-T3", "--open", "-p", "22,23,80,443,161,162", "-oN", str(ev / f"v321-network-device-{slug}.txt"), host], "R1_bounded_discovery"))
    elif surface == "cellular_telecom":
        out.append(("nmap", ["nmap", "-sV", "-T3", "--open", "-p", "80,443,8080,8443", "-oN", str(ev / f"v321-cellular-path-{slug}.txt"), host], "R1_bounded_discovery"))
        out.append(("httpx", ["httpx", "-u", url, "-silent", "-status-code", "-title", "-tech-detect", "-json", "-o", str(ev / f"v321-cellular-http-{slug}.jsonl")], "R1_bounded_discovery"))
    return out


def _reachability(target: str) -> dict[str, Any]:
    host = _host(target)
    result: dict[str, Any] = {"target": target, "host": host, "dns": None, "ipv4": [], "ipv6": [], "error": ""}
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        ips = sorted({x[4][0] for x in infos})
        result["ipv4"] = [x for x in ips if ":" not in x]
        result["ipv6"] = [x for x in ips if ":" in x]
        result["dns"] = "resolved" if ips else "no-addresses"
    except OSError as exc:
        result["dns"] = "failed"
        result["error"] = str(exc)
    return result


def _scope_ok(target: str, scope_file: str | Path | None) -> tuple[bool, str]:
    if not scope_file or not Path(scope_file).is_file():
        return False, "scope-file-missing"
    try:
        allowed = load_scope(str(scope_file))
    except (OSError, UnicodeError, ValueError) as exc:
        return False, f"scope-read-failed:{exc}"
    if not allowed:
        return False, "scope-empty"
    try:
        return (True, "in-scope") if in_scope(target, allowed) else (False, "target-out-of-scope")
    except (TypeError, ValueError) as exc:
        return False, f"scope-check-failed:{exc}"


def execute_universal_assessment(
    root: str | Path,
    *,
    target: str,
    scope_file: str | Path | None,
    perspective: str = "internet_ipv4",
    authorized: bool = False,
    execute: bool = False,
    surfaces: Iterable[str] | None = None,
    max_steps: int = 12,
    timeout: int = 600,
) -> dict[str, Any]:
    """Run bounded registered adapters and produce complete coverage accounting."""
    root = Path(root)
    if perspective not in PERSPECTIVES:
        raise ValueError(f"unknown perspective: {perspective}")
    if max_steps < 1 or max_steps > MAX_STEPS:
        raise ValueError(f"max_steps must be 1-{MAX_STEPS}")
    if timeout < 1 or timeout > MAX_TIMEOUT:
        raise ValueError(f"timeout must be 1-{MAX_TIMEOUT}")

    selected = list(surfaces) if surfaces else list(ATTACK_SURFACES)
    selected = list(dict.fromkeys(str(s) for s in selected))
    invalid_surfaces = [s for s in selected if s not in ATTACK_SURFACES]
    selected = [s for s in selected if s in ATTACK_SURFACES]
    scope_ok, scope_reason = _scope_ok(target, scope_file)
    plan = build_functional_assessment_plan(root, target=target, perspective=perspective, requested_surfaces=selected, authorized=authorized)
    reach = _reachability(target)

    result = {
        "schema_version": VERSION,
        "target": target,
        "perspective": perspective,
        "perspective_origin": PERSPECTIVES[perspective],
        "authorization_asserted": bool(authorized),
        "execute_requested": bool(execute),
        "scope": {"ok": scope_ok, "reason": scope_reason},
        "reachability": reach,
        "status": "planned",
        "steps": [],
        "coverage": {"selected": len(selected), "invalid": len(invalid_surfaces), "executed": 0, "attempted": 0, "succeeded": 0, "blocked": 0, "specialist_required": 0, "skipped": 0},
        "input_validation": {"invalid_surfaces": invalid_surfaces, "unknown_inputs_are_errors": True},
        "safety": {
            "execution_classes": ["R0_observe", "R1_bounded_discovery", "R2_non_destructive_verify"],
            "arbitrary_shell": False,
            "scope_expansion": False,
            "credential_capture": False,
            "persistence": False,
            "destructive_actions": False,
            "carrier_bypass": False,
            "note": "cellular/internet perspective requires the operator to run the platform from that network vantage; no network access-control bypass is attempted",
        },
    }

    if not authorized or not execute:
        result["status"] = "plan-only"
        result["coverage"]["skipped"] = len(selected)
        _write(root, "universal-assessment-v321.json", result)
        return result
    if not scope_ok:
        result["status"] = "blocked"
        result["coverage"]["blocked"] = len(selected)
        _write(root, "universal-assessment-v321.json", result)
        return result

    start = time.monotonic()
    executed = 0
    for surface in selected:
        if executed >= max_steps:
            result["coverage"]["skipped"] += 1
            result["steps"].append({"surface": surface, "status": "skipped", "reason": "max-steps-reached"})
            continue
        actions = _adapter_actions(surface, target, root)
        if not actions:
            result["coverage"]["specialist_required"] += 1
            result["steps"].append({
                "surface": surface,
                "status": "specialist-required",
                "adapters": EXECUTION_ADAPTERS.get(surface, []),
                "tests": ATTACK_SURFACES[surface]["tests"],
                "reason": "no generic safe ToolManager adapter; use the registered specialist/lab/artifact workflow",
            })
            continue
        for tool, argv, execution_class in actions:
            if executed >= max_steps:
                result["coverage"]["skipped"] += 1
                result["steps"].append({"surface": surface, "tool": tool, "status": "skipped", "reason": "max-steps-reached"})
                continue
            row: dict[str, Any] = {
                "step_id": "V321-" + _hash(target, perspective, surface, tool),
                "surface": surface,
                "perspective": perspective,
                "tool": tool,
                "execution_class": execution_class,
                "argv": [str(x) for x in argv],
                "started": time.time(),
            }
            try:
                proc = run_tool(root, tool, argv, timeout=timeout)
                row.update({
                    "status": "executed" if proc.returncode == 0 else "failed",
                    "returncode": proc.returncode,
                    "stdout_bytes": len((proc.stdout or "").encode()),
                    "stderr_bytes": len((proc.stderr or "").encode()),
                })
            except FileNotFoundError as exc:
                row.update({"status": "blocked", "reason": "tool-unavailable", "detail": str(exc)})
            except (ValueError, RuntimeError, OSError) as exc:
                row.update({"status": "blocked", "reason": "tool-execution-rejected", "detail": str(exc)})
            except Exception as exc:
                row.update({"status": "failed", "reason": "unexpected-tool-error", "detail": str(exc)})
            row["finished"] = time.time()
            row["duration_seconds"] = round(row["finished"] - row["started"], 3)
            result["steps"].append(row)
            executed += 1
            result["coverage"]["attempted"] += 1
            if row["status"] == "executed":
                result["coverage"]["executed"] += 1
                result["coverage"]["succeeded"] += 1
            elif row["status"] == "failed":
                result["coverage"]["executed"] += 1
            elif row["status"] == "blocked":
                result["coverage"]["blocked"] += 1

        if time.monotonic() - start >= timeout:
            result["coverage"]["skipped"] += max(0, len(selected) - len({x.get("surface") for x in result["steps"] if isinstance(x, dict)}))
            result["status"] = "partial"
            result["budget_exhausted"] = True
            break

    if result["coverage"]["executed"] and not result["coverage"]["blocked"]:
        result["status"] = "completed"
    elif result["coverage"]["executed"] or result["coverage"]["specialist_required"] or result["coverage"]["blocked"]:
        result["status"] = "partial"
    else:
        result["status"] = "blocked"
    result["coverage"]["uncovered"] = len(selected) - result["coverage"]["executed"] - result["coverage"]["specialist_required"] - result["coverage"]["skipped"]
    result["coverage"]["coverage_ratio"] = round(result["coverage"]["succeeded"] / len(selected), 3) if selected else None
    _write(root, "universal-assessment-v321.json", result)
    return result
