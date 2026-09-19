"""Cross-ecosystem capability fabric for v3.10.

This module adds *interoperability and reasoning* rather than copying third-party
security-tool implementations. It turns common specialist-tool artifacts into a
shared, provenance-preserving observation model and produces bounded next-step
plans. It never grants authorization and never launches C2, payloads, credential
capture, persistence, evasion, or arbitrary commands.
"""
from __future__ import annotations
import hashlib, json
from pathlib import Path
from typing import Any, Iterable
from modules.atomic_io import atomic_write_json

VERSION = "3.10"

CAPABILITIES: dict[str, dict[str, Any]] = {
    "recon": {"projects": ["Subfinder", "Amass", "httpx", "Naabu", "Nmap", "Katana"], "mode": "scoped-tool-or-evidence"},
    "vulnerability_discovery": {"projects": ["Nuclei", "Metasploit Framework"], "mode": "scoped-tool-or-evidence"},
    "ad_attack_paths": {"projects": ["BloodHound CE", "NetExec", "Impacket"], "mode": "offline-analysis-or-read-only-tool"},
    "mobile_analysis": {"projects": ["MobSF", "Frida"], "mode": "offline-report-or-operator-runtime-evidence"},
    "credential_audit": {"projects": ["Hashcat"], "mode": "offline-result-import"},
    "red_team_c2": {"projects": ["Sliver", "Havoc"], "mode": "human-operated-lab-only"},
    "internal_network_research": {"projects": ["Responder"], "mode": "human-operated-lab-only"},
}

HIGH_RISK = {"red_team_c2", "internal_network_research"}


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8", errors="replace"))


def _rows(path: Path) -> Iterable[dict[str, Any]]:
    obj = _read_json(path)
    if isinstance(obj, list):
        yield from (x for x in obj if isinstance(x, dict))
    elif isinstance(obj, dict):
        if isinstance(obj.get("data"), list):
            yield from (x for x in obj["data"] if isinstance(x, dict))
        elif isinstance(obj.get("findings"), list):
            yield from (x for x in obj["findings"] if isinstance(x, dict))
        else:
            yield obj


def _write(root: Path, name: str, data: dict[str, Any]) -> dict[str, Any]:
    ev = root / "evidence"
    ev.mkdir(parents=True, exist_ok=True)
    atomic_write_json(ev / name, data)
    return data


def _obs(source: str, kind: str, title: str, *, severity: str = "unknown", target: str | None = None,
         evidence: Any = None, confidence: str = "imported", refs: list[str] | None = None) -> dict[str, Any]:
    return {
        "source": source, "kind": kind, "title": title, "severity": severity,
        "target": target, "confidence": confidence, "evidence": evidence,
        "references": refs or [], "validation_state": "candidate",
    }


def import_netexec(root: str | Path, source: str | Path) -> dict[str, Any]:
    """Normalize operator-supplied NetExec JSON/JSONL output without executing NetExec."""
    root, source = Path(root), Path(source)
    if not source.is_file() or source.stat().st_size > 100 * 1024 * 1024:
        return {"status": "blocked", "reason": "netexec-result-required-and-size-limited"}
    try:
        rows = list(_rows(source))
    except json.JSONDecodeError as exc:
        return {"status": "blocked", "reason": f"invalid-json:{exc}"}
    observations = []
    for r in rows[:10000]:
        observations.append(_obs("NetExec", "ad-enumeration", str(r.get("message") or r.get("hostname") or "NetExec observation"),
                                 target=r.get("host") or r.get("target") or r.get("hostname"), evidence=r))
    return _write(root, "netexec-import-v310.json", {"schema_version": VERSION, "status": "completed",
        "mode": "offline-netexec-result", "source_sha256": _sha256(source), "observations": observations,
        "limitations": ["No network requests or authentication attempts are performed by the importer.",
                         "Imported observations remain candidates until independently validated."]})


def import_frida(root: str | Path, source: str | Path) -> dict[str, Any]:
    """Normalize exported Frida/runtime observations (JSON/JSONL)."""
    root, source = Path(root), Path(source)
    if not source.is_file() or source.stat().st_size > 100 * 1024 * 1024:
        return {"status": "blocked", "reason": "frida-result-required-and-size-limited"}
    try:
        rows = list(_rows(source))
    except json.JSONDecodeError as exc:
        return {"status": "blocked", "reason": f"invalid-json:{exc}"}
    observations = [_obs("Frida", "runtime-instrumentation", str(r.get("message") or r.get("function") or r.get("event") or "Frida observation"),
                          target=r.get("process") or r.get("package") or r.get("target"), evidence=r) for r in rows[:10000]]
    return _write(root, "frida-import-v310.json", {"schema_version": VERSION, "status": "completed",
        "mode": "offline-frida-evidence", "source_sha256": _sha256(source), "observations": observations})


def import_hashcat(root: str | Path, source: str | Path) -> dict[str, Any]:
    """Import a credential-audit result without handling live credential material."""
    root, source = Path(root), Path(source)
    if not source.is_file() or source.stat().st_size > 50 * 1024 * 1024:
        return {"status": "blocked", "reason": "hashcat-result-required-and-size-limited"}
    text = source.read_text(encoding="utf-8", errors="replace")
    lines = [x for x in text.splitlines() if x.strip()][:10000]
    # Deliberately store only counts/categories, not recovered secrets.
    recovered = sum(1 for x in lines if ":" in x)
    return _write(root, "hashcat-import-v310.json", {"schema_version": VERSION, "status": "completed",
        "mode": "offline-credential-audit", "source_sha256": _sha256(source),
        "records_seen": len(lines), "records_resembling_recovered_entries": recovered,
        "secret_material_retained": False,
        "limitations": ["The importer does not execute Hashcat and intentionally does not retain recovered passwords or tokens."]})


def import_metasploit(root: str | Path, source: str | Path) -> dict[str, Any]:
    """Import a Metasploit/RPC-style exported result as evidence only."""
    root, source = Path(root), Path(source)
    if not source.is_file() or source.stat().st_size > 100 * 1024 * 1024:
        return {"status": "blocked", "reason": "metasploit-result-required-and-size-limited"}
    try:
        obj = _read_json(source)
    except json.JSONDecodeError as exc:
        return {"status": "blocked", "reason": f"invalid-json:{exc}"}
    rows = list(_rows(source))
    observations = []
    for r in rows[:10000]:
        title = str(r.get("name") or r.get("module") or r.get("title") or "Metasploit observation")
        observations.append(_obs("Metasploit Framework", "validated-or-reported-result", title,
                                 severity=str(r.get("severity") or "unknown"), target=r.get("host") or r.get("target"), evidence=r))
    return _write(root, "metasploit-import-v310.json", {"schema_version": VERSION, "status": "completed",
        "mode": "offline-metasploit-evidence", "source_sha256": _sha256(source), "observations": observations,
        "raw_shape": type(obj).__name__, "limitations": ["The platform does not launch exploit modules from this importer.",
        "Imported results remain candidates until platform evidence validation succeeds."]})


def import_responder(root: str | Path, source: str | Path) -> dict[str, Any]:
    """Summarize a Responder/log export without parsing or retaining captured secrets."""
    root, source = Path(root), Path(source)
    if not source.is_file() or source.stat().st_size > 50 * 1024 * 1024:
        return {"status": "blocked", "reason": "responder-log-required-and-size-limited"}
    lines = [x for x in source.read_text(encoding="utf-8", errors="replace").splitlines() if x.strip()]
    keywords = ("SMB", "HTTP", "LDAP", "NTLM", "LLMNR", "NBNS", "MDNS")
    events = sum(any(k.lower() in line.lower() for k in keywords) for line in lines)
    return _write(root, "responder-import-v310.json", {"schema_version": VERSION, "status": "completed",
        "mode": "offline-responder-log", "source_sha256": _sha256(source), "lines_seen": len(lines),
        "network_event_lines": events, "secret_material_retained": False,
        "limitations": ["No poisoning, capture, relay, or live network operation is performed."]})


def capability_matrix(root: str | Path, installed_tools: list[str] | None = None) -> dict[str, Any]:
    installed = {x.lower() for x in (installed_tools or [])}
    rows = []
    for key, meta in CAPABILITIES.items():
        available = any(p.lower() in installed for p in meta["projects"])
        rows.append({"capability": key, "projects": meta["projects"], "mode": meta["mode"],
                     "high_risk": key in HIGH_RISK, "available_in_deployment": available,
                     "platform_layer": "policy + orchestration + evidence + normalization"})
    return _write(Path(root), "ecosystem-capability-matrix-v310.json", {"schema_version": VERSION,
        "status": "completed", "capabilities": rows,
        "design_principle": "compose specialist engines; do not copy their implementations",
        "authority_boundary": "Imported data and specialist outputs never grant authorization or expand engagement scope."})


def build_cross_domain_plan(root: str | Path, *, observations: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Correlate imported observations into bounded investigation categories."""
    observations = observations or []
    plan: list[dict[str, Any]] = []
    seen = set()
    for o in observations:
        title = str(o.get("title") or "observation")
        kind = str(o.get("kind") or "unknown")
        key = (kind, title.lower())
        if key in seen:
            continue
        seen.add(key)
        if "ad" in kind or "bloodhound" in str(o.get("source", "")).lower():
            next_step = "validate AD relationship/permission evidence inside the approved engagement"
        elif "mobile" in kind or o.get("source") in {"MobSF", "Frida"}:
            next_step = "correlate mobile finding with static/runtime evidence and application version"
        elif "vulnerability" in kind or o.get("source") in {"Nuclei", "Metasploit Framework"}:
            next_step = "independently validate the finding with a bounded, non-destructive proof"
        else:
            next_step = "correlate with existing asset, service and evidence records"
        plan.append({"observation": title, "category": kind, "next_step": next_step,
                     "authorization_required": True, "scope_recheck_required": True})
    return _write(Path(root), "cross-domain-investigation-plan-v310.json", {"schema_version": VERSION,
        "status": "completed", "items": plan[:5000],
        "principles": ["No item executes automatically", "Every active step re-checks authorization and scope",
                       "Imported evidence remains untrusted until validated"]})
