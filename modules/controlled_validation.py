#!/usr/bin/env python3
"""Controlled Validation Mode (CVM) for authorized assessments.

CVM is deliberately narrow: it validates that a reported web target is reachable
and records non-destructive HTTP/TLS observations. It does not generate or run
exploit payloads, execute arbitrary commands, pivot, persist, dump credentials,
or exfiltrate data.
"""
from __future__ import annotations

import hashlib
import json
import socket
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from modules.findings_io import load_findings_file
from modules.safe_http import request as safe_request

VALID_MODES = {"observe", "verify", "impact"}
MAX_TIMEOUT = 15
USER_AGENT = "PentestAutomationFramework-CVM/1.0"


def load_finding(outdir: str | Path, finding_id: str) -> dict | None:
    root = Path(outdir)
    candidates = [
        root / "vulns" / "findings.json",
        root / "vulns" / "authenticated-findings.json",
        root / "api" / "api-findings.json",
        root / "servers" / "server-findings.json",
        root / "internal" / "internal-findings.json",
    ]
    needle = finding_id.strip()
    for path in candidates:
        for item in load_findings_file(path):
            supplied = str(item.get("finding_id") or item.get("id") or item.get("template-id") or "")
            name = str((item.get("info") or {}).get("name") or "")
            host = str(item.get("matched-at") or item.get("host") or "")
            seed = "|".join([supplied, _asset(host), host, name])
            fid = "F-" + hashlib.sha256(seed.encode()).hexdigest()[:12]
            if needle in {fid, supplied}:
                item["_cvm_id"] = fid
                return item
    # Also support IDs from the generated attack graph.
    graph = root / "evidence" / "attack-graph.json"
    if graph.exists():
        try:
            data = json.loads(graph.read_text(encoding="utf-8"))
            for node in data.get("nodes", []):
                if node.get("type") == "finding" and needle in {node.get("id"), node.get("finding_id")}:
                    return {"_graph_node": node, "_cvm_id": node.get("id")}
        except json.JSONDecodeError:
            pass
    return None


def _asset(value: str) -> str:
    value = str(value or "").strip()
    parsed = urlparse(value if "://" in value else "//" + value)
    return (parsed.hostname or value.split("/", 1)[0]).lower().rstrip(".")


def _target_from_finding(finding: dict) -> str:
    return str(finding.get("matched-at") or finding.get("host") or "").strip()


def _url_candidates(target: str) -> list[str]:
    if not target:
        return []
    if target.startswith(("http://", "https://")):
        return [target]
    return [f"https://{target}", f"http://{target}"]


def _in_scope(target: str, scope_file: str | Path) -> bool:
    """Fail-closed on scope questions, but don't let a genuine bug in the
    scope loader masquerade as 'target not in scope' — those need very
    different responses from an operator debugging a run."""
    from modules.scope import load_scope, filter_in_scope
    allowed = load_scope(scope_file)
    if not allowed:
        return False
    return bool(filter_in_scope([_asset(target)], allowed=allowed))


def _http_head(url: str) -> dict:
    """HEAD observation via the shared non-redirect-following request helper.

    A 3xx response is surfaced as-is (with the Location header, if any) --
    it is never followed. Following a redirect here would mean issuing a
    live request to a host that was never scope-checked.
    """
    started = time.monotonic()
    result = safe_request(url, method="HEAD", headers={"User-Agent": USER_AGENT}, timeout=MAX_TIMEOUT)
    result["elapsed_seconds"] = round(time.monotonic() - started, 3)
    if result.get("ok"):
        headers = result.pop("headers", {}) or {}
        result["server"] = headers.get("Server", "")
        result["content_type"] = headers.get("Content-Type", "")
        result["content_length"] = headers.get("Content-Length", "")
        if "location" in result:
            result["note"] = "Server returned a redirect; it was recorded but not followed."
    result.pop("body", None)
    return result


def _tls_observation(url: str) -> dict:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return {"checked": False}
    port = parsed.port or 443
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((parsed.hostname, port), timeout=MAX_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=parsed.hostname) as tls:
                cert = tls.getpeercert()
                return {
                    "checked": True,
                    "tls_version": tls.version(),
                    "cipher": tls.cipher()[0] if tls.cipher() else "",
                    "subject": str(cert.get("subject", ""))[:300],
                    "issuer": str(cert.get("issuer", ""))[:300],
                    "not_after": cert.get("notAfter", ""),
                }
    except Exception as exc:
        return {"checked": True, "error": type(exc).__name__, "detail": str(exc)[:200]}


def _write_ledger(outdir: Path, entry: dict) -> Path:
    path = outdir / "evidence" / "validation-ledger.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    data = []
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, list):
                data = []
        except json.JSONDecodeError:
            data = []
    data.append(entry)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


def validate(outdir: str | Path, finding_id: str, mode: str, scope_file: str | Path, approved: bool = False) -> dict:
    """Run a bounded, non-destructive validation observation."""
    root = Path(outdir)
    mode = mode.lower().strip()
    if mode not in VALID_MODES:
        raise ValueError(f"Invalid CVM mode. Use: {', '.join(sorted(VALID_MODES))}")
    if not approved:
        raise PermissionError("Explicit operator approval is required")

    finding = load_finding(root, finding_id)
    if not finding:
        raise ValueError(f"Finding not found: {finding_id}")
    target = _target_from_finding(finding)
    asset = _asset(target)
    if not target or not asset:
        raise ValueError("Finding does not contain a usable target")
    if not _in_scope(target, scope_file):
        raise PermissionError("Target is not in the authorized scope")

    validation_id = "V-" + hashlib.sha256(f"{finding_id}|{datetime.now(timezone.utc).isoformat()}".encode()).hexdigest()[:10]
    started = datetime.now(timezone.utc).isoformat()
    result = {
        "validation_id": validation_id,
        "finding_id": finding_id,
        "mode": mode,
        "target": target,
        "asset": asset,
        "authorization": "approved-by-operator",
        "scope_checked": True,
        "destructive_actions": False,
        "exploit_payloads": False,
        "arbitrary_commands": False,
        "persistence": False,
        "credential_access": False,
        "lateral_movement": False,
        "exfiltration": False,
        "started": started,
        "result": "manual-review-required",
        "observations": [],
    }

    if mode == "impact":
        result["observations"].append("Impact mode is documentation-only; no impact action was executed by CVM.")
        result["recommended_manual_action"] = "Assess impact using the engagement-approved procedure and record evidence separately."
    else:
        urls = _url_candidates(target)
        if not urls:
            result["observations"].append("No HTTP(S) target was derivable from the finding; manual validation is required.")
        else:
            for url in urls:
                obs = _http_head(url)
                obs["url"] = url
                result["observations"].append(obs)
                if obs.get("ok"):
                    result["tls"] = _tls_observation(url)
                    if obs.get("location"):
                        # A 3xx was returned; it was recorded but not followed,
                        # so this only confirms the ORIGINAL URL is reachable,
                        # not whatever host the Location header points to.
                        result["result"] = "reachable-observed-redirect-not-followed"
                    else:
                        result["result"] = "reachable-observed"
                    break
            result["recommended_manual_action"] = "Compare the observation with the reported finding and capture minimal evidence before changing finding status."

    result["completed"] = datetime.now(timezone.utc).isoformat()
    ledger = _write_ledger(root, result)
    result["ledger"] = str(ledger.relative_to(root))

    report = root / "reports" / "controlled-validation.md"
    report.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Controlled Validation Record", "",
        f"- Validation: `{validation_id}`",
        f"- Finding: `{finding_id}`",
        f"- Mode: `{mode}`",
        f"- Target: `{target}`",
        f"- Scope: **checked**",
        f"- Operator approval: **recorded**",
        f"- Result: `{result['result']}`", "",
        "## Safety Boundary", "",
        "CVM performed only bounded, non-destructive observations. It did not execute exploit payloads, arbitrary commands, persistence, credential access, lateral movement, or exfiltration.", "",
        "## Observations", "",
    ]
    for obs in result["observations"]:
        lines.append(f"- `{json.dumps(obs, ensure_ascii=False)}`")
    lines += ["", "## Next Manual Step", "", result.get("recommended_manual_action", "Review the finding manually and record evidence.") + "", ""]
    report.write_text("\n".join(lines), encoding="utf-8")
    result["report"] = str(report.relative_to(root))
    return result
