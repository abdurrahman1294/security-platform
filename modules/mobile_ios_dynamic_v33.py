"""Bounded iOS Simulator runtime inspection.

The live path uses only fixed, read-oriented ``xcrun simctl`` operations.  It
never accepts arbitrary shell commands.  A simulator export JSON can also be
analysed offline, which keeps CI and Linux deployments useful.
"""
from __future__ import annotations
import json, re, shutil, hashlib
from pathlib import Path
from modules.atomic_io import atomic_write_json
from modules.governed_process_v335 import run_fixed

VERSION = "3.3"
MAX_OUTPUT = 120_000


def _run(argv, timeout=30):
    if not argv:
        return {"returncode": None, "stdout": "", "stderr": "empty-argv"}
    tool = Path(argv[0]).name
    return run_fixed(tool, argv, timeout=timeout)


def _simctl():
    xcrun = shutil.which("xcrun")
    return [xcrun, "simctl"] if xcrun else None


def _json_output(result):
    try:
        return json.loads(result.get("stdout", ""))
    except (TypeError, json.JSONDecodeError):
        return None

def _app_inventory(raw: str):
    """Extract bundle identifiers from simctl listapps output without trusting arbitrary data."""
    ids = sorted(set(re.findall(r'"?([A-Za-z0-9][A-Za-z0-9.-]{2,199})"?\s*=\s*\{', raw or "")))
    return {x: {} for x in ids[:500]}


def assess_export(root: str | Path, source: str | Path) -> dict:
    root = Path(root); ev = root / "evidence"; ev.mkdir(parents=True, exist_ok=True)
    p = Path(source)
    if not p.is_file():
        return {"status": "blocked", "reason": "runtime-export-required"}
    try:
        raw = p.read_bytes()
        doc = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return {"status": "blocked", "reason": f"invalid-runtime-export:{exc}"}
    if not isinstance(doc, dict):
        return {"status": "blocked", "reason": "runtime-export-object-required"}
    result = _analyse(root, doc, mode="offline-export")
    result["source_sha256"] = hashlib.sha256(raw).hexdigest()
    atomic_write_json(ev / "ios-dynamic-v33.json", result)
    return result


def _analyse(root: Path, doc: dict, *, mode: str) -> dict:
    apps = doc.get("apps", {})
    if isinstance(apps, list):
        app_rows = apps[:500]
    elif isinstance(apps, dict):
        app_rows = [{"bundle_id": k, **(v if isinstance(v, dict) else {})} for k, v in list(apps.items())[:500]]
    else:
        app_rows = []
    processes = doc.get("processes", [])
    if not isinstance(processes, list): processes = []
    logs = doc.get("logs", [])
    if not isinstance(logs, list): logs = []
    findings = []
    bundle_id = str(doc.get("bundle_id", ""))
    target_apps = [a for a in app_rows if not bundle_id or str(a.get("bundle_id", "")) == bundle_id]
    if bundle_id and not target_apps:
        findings.append({"id": "IOS-DYN-NOT-INSTALLED", "title": "Target application not observed in simulator app inventory", "severity": "info"})
    joined_logs = "\n".join(str(x) for x in logs[-500:])
    if re.search(r"(?i)(exception|fatal|crash|jetsam|terminated)", joined_logs):
        findings.append({"id": "IOS-DYN-RUNTIME-ERROR", "title": "Runtime error/crash indicators observed", "severity": "medium", "evidence": "redacted-log-marker"})
    if re.search(r"(?i)(http://|ats|cleartext)", joined_logs):
        findings.append({"id": "IOS-DYN-CLEARTEXT", "title": "Runtime logs contain cleartext/ATS-related indicators", "severity": "medium", "evidence": "redacted-runtime-marker"})
    if re.search(r"(?i)(keychain|credential|password|authorization|bearer)", joined_logs):
        findings.append({"id": "IOS-DYN-SENSITIVE-FLOW", "title": "Sensitive-data/runtime-security markers observed", "severity": "info", "evidence": "redacted-runtime-marker"})
    return {
        "schema_version": VERSION, "status": "completed", "mode": mode,
        "bundle_id": bundle_id, "apps": target_apps, "process_count": len(processes),
        "processes": processes[:500], "log_sample_count": min(len(logs), 500),
        "findings": findings,
        "limitations": [
            "Runtime observations depend on the supplied simulator state/log export.",
            "This component does not bypass application controls, jailbreak devices, inject code, or capture secrets.",
            "A clean runtime sample is not proof that a vulnerability is absent.",
        ],
    }


def inspect_simulator(root: str | Path, *, bundle_id: str = "", device: str = "booted", allow_launch: bool = False) -> dict:
    root = Path(root); ev = root / "evidence"; ev.mkdir(parents=True, exist_ok=True)
    simctl = _simctl()
    if not simctl:
        return {"status": "blocked", "reason": "xcrun-not-installed"}
    if device != "booted" and not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", device):
        return {"status": "blocked", "reason": "invalid-simulator-identifier"}
    commands = [
        ("device-list", simctl + ["list", "devices", "available", "-j"]),
        ("app-inventory", simctl + ["listapps", device]),
        ("process-list", simctl + ["spawn", device, "ps", "-A"]),
    ]
    results = {}
    for name, argv in commands:
        r = _run(argv)
        results[name] = {"returncode": r["returncode"], "stdout": r["stdout"], "stderr": r["stderr"]}
    if bundle_id and allow_launch:
        # Explicitly opt-in, still constrained to a simulator and exact bundle ID.
        if not re.fullmatch(r"[A-Za-z0-9.-]{1,200}", bundle_id):
            return {"status": "blocked", "reason": "invalid-bundle-id"}
        r = _run(simctl + ["launch", device, bundle_id], timeout=30)
        results["launch"] = {"returncode": r["returncode"], "stdout": r["stdout"], "stderr": r["stderr"]}
    apps = _json_output(results["app-inventory"]) or _app_inventory(results["app-inventory"]["stdout"])
    processes = [line for line in results["process-list"]["stdout"].splitlines() if line.strip()][:500]
    doc = {"bundle_id": bundle_id, "apps": apps, "processes": processes, "logs": []}
    out = _analyse(root, doc, mode="live-simulator")
    out["device"] = device
    out["commands"] = {k: v["returncode"] for k, v in results.items()}
    out["launch_requested"] = bool(bundle_id and allow_launch)
    atomic_write_json(ev / "ios-dynamic-v33.json", out)
    return out
