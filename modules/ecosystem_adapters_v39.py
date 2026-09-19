"""Open-source ecosystem bridge for the security platform.

This module integrates *evidence and analysis* from major open-source security
projects without copying their code or turning the platform into an
unrestricted offensive launcher. High-risk C2/payload/evasion capabilities are
catalogued as external/lab-only capabilities and are never auto-executed.

Supported evidence families:
- BloodHound CE JSON exports -> AD graph/attack-path candidates
- MobSF JSON reports -> mobile findings/technology evidence
- Nuclei/ProjectDiscovery findings -> normalized findings
- Metasploit/Sliver/Havoc/Impacket/NetExec/Frida/Hashcat/Responder metadata
  -> capability inventory and integration gap report
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from modules.atomic_io import atomic_write_json
from modules.findings_io import load_findings_file

VERSION = "3.9"

ECOSYSTEMS: dict[str, dict[str, Any]] = {
    "projectdiscovery": {
        "projects": ["subfinder", "httpx", "naabu", "katana", "nuclei", "dnsx", "amass"],
        "strengths": ["attack-surface discovery", "HTTP probing", "port discovery", "crawling", "vulnerability templates"],
        "integration": "native-toolchain-or-evidence-import",
    },
    "metasploit": {
        "projects": ["Metasploit Framework"],
        "strengths": ["exploit-module ecosystem", "payload/session ecosystem", "post-exploitation module catalog"],
        "integration": "catalog-and-lab-only-bridge",
    },
    "sliver": {
        "projects": ["Sliver"],
        "strengths": ["adversary emulation", "C2", "post-exploitation"],
        "integration": "catalog-and-lab-only-bridge",
    },
    "havoc": {
        "projects": ["Havoc"],
        "strengths": ["malleable C2", "agent architecture", "post-exploitation"],
        "integration": "catalog-and-lab-only-bridge",
    },
    "impacket": {
        "projects": ["Impacket"],
        "strengths": ["Windows protocols", "SMB", "Kerberos", "AD protocol research"],
        "integration": "offline-evidence-and-read-only-analysis",
    },
    "netexec": {
        "projects": ["NetExec"],
        "strengths": ["SMB/WinRM/LDAP enumeration", "AD discovery"],
        "integration": "allowlisted-read-only-adapter",
    },
    "bloodhound": {
        "projects": ["BloodHound Community Edition"],
        "strengths": ["AD/Azure graph analysis", "attack-path discovery"],
        "integration": "offline-export-analysis",
    },
    "mobsf": {
        "projects": ["MobSF"],
        "strengths": ["Android/iOS static analysis", "mobile dynamic-analysis evidence", "API-driven reports"],
        "integration": "offline-report-import",
    },
    "frida": {
        "projects": ["Frida"],
        "strengths": ["runtime instrumentation", "mobile/application research"],
        "integration": "operator-supplied-runtime-evidence",
    },
    "hashcat": {
        "projects": ["Hashcat"],
        "strengths": ["offline credential-audit workloads"],
        "integration": "result-import-only",
    },
    "responder": {
        "projects": ["Responder"],
        "strengths": ["internal-network credential-capture research"],
        "integration": "catalog-and-lab-only-bridge",
    },
}


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _walk_objects(value: Any):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk_objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_objects(child)


def import_bloodhound(root: str | Path, source: str | Path) -> dict[str, Any]:
    """Import a BloodHound-style JSON export without contacting a directory."""
    root, source = Path(root), Path(source)
    if not source.is_file() or source.stat().st_size > 100 * 1024 * 1024:
        return {"status": "blocked", "reason": "bloodhound-json-required-and-size-limited"}
    try:
        obj = json.loads(source.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        return {"status": "blocked", "reason": f"invalid-json:{exc}"}

    records = list(_walk_objects(obj))
    edges: list[dict[str, Any]] = []
    nodes: list[dict[str, Any]] = []
    interesting = {"genericall", "genericwrite", "writedacl", "writeowner", "forcechangepassword", "addmember", "adminsdholder", "memberof", "hasession", "canrdp", "canpsremote"}
    for rec in records:
        props = rec.get("Properties") if isinstance(rec.get("Properties"), dict) else rec
        label = str(rec.get("label") or rec.get("type") or rec.get("kind") or "").lower()
        if any(k in rec for k in ("source", "target", "src", "dst")):
            relation = str(rec.get("label") or rec.get("relation") or rec.get("edge") or label).lower()
            if relation in interesting or any(x in relation for x in interesting):
                edges.append({"source": rec.get("source") or rec.get("src"), "target": rec.get("target") or rec.get("dst"), "relation": relation})
        if props and any(k in props for k in ("name", "samaccountname", "domain", "objectid")):
            nodes.append({k: props.get(k) for k in ("name", "samaccountname", "domain", "objectid") if props.get(k) is not None})

    data = {
        "schema_version": VERSION,
        "status": "completed",
        "mode": "offline-bloodhound-export",
        "source_sha256": _sha256(source),
        "records_scanned": len(records),
        "nodes": nodes[:5000],
        "interesting_edges": edges[:5000],
        "limitations": [
            "Offline export analysis only; no AD/Azure queries are performed.",
            "Edges are attack-path candidates until independently validated.",
            "No credentials, tickets, ACLs, group membership, or sessions are modified.",
        ],
    }
    ev = root / "evidence"
    ev.mkdir(parents=True, exist_ok=True)
    atomic_write_json(ev / "bloodhound-import-v39.json", data)
    return data


def import_mobsf(root: str | Path, source: str | Path) -> dict[str, Any]:
    """Normalize an exported MobSF report into platform findings."""
    root, source = Path(root), Path(source)
    if not source.is_file() or source.stat().st_size > 100 * 1024 * 1024:
        return {"status": "blocked", "reason": "mobsf-report-required-and-size-limited"}
    try:
        obj = json.loads(source.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        return {"status": "blocked", "reason": f"invalid-json:{exc}"}

    findings: list[dict[str, Any]] = []
    for rec in _walk_objects(obj):
        if not isinstance(rec, dict):
            continue
        title = rec.get("title") or rec.get("name") or rec.get("issue")
        severity = rec.get("severity") or rec.get("level")
        if title and severity:
            findings.append({
                "source": "MobSF",
                "title": str(title),
                "severity": str(severity).lower(),
                "confidence": "imported",
            })

    data = {
        "schema_version": VERSION,
        "status": "completed",
        "mode": "offline-mobsf-report",
        "source_sha256": _sha256(source),
        "findings": findings[:5000],
        "raw_report_not_rewritten": True,
        "limitations": ["Imported findings retain MobSF provenance and require platform validation rules before being treated as confirmed vulnerabilities."],
    }
    ev = root / "evidence"
    ev.mkdir(parents=True, exist_ok=True)
    atomic_write_json(ev / "mobsf-import-v39.json", data)
    return data


def import_findings(root: str | Path, source: str | Path, *, source_name: str = "external") -> dict[str, Any]:
    """Import JSON/JSONL findings from Nuclei or another compatible scanner."""
    root, source = Path(root), Path(source)
    if not source.is_file() or source.stat().st_size > 100 * 1024 * 1024:
        return {"status": "blocked", "reason": "findings-file-required-and-size-limited"}
    rows = load_findings_file(source)
    normalized = []
    for row in rows:
        normalized.append({
            "source": source_name,
            "title": row.get("name") or row.get("info", {}).get("name") or row.get("template-id") or "external-finding",
            "severity": str(row.get("severity") or row.get("info", {}).get("severity") or "unknown").lower(),
            "target": row.get("host") or row.get("matched-at") or row.get("url") or row.get("target"),
            "template_id": row.get("template-id"),
            "evidence": row.get("matcher-name") or row.get("extracted-results") or row.get("response") or None,
            "validation_state": "candidate",
        })
    data = {"schema_version": VERSION, "status": "completed", "source": source_name, "source_sha256": _sha256(source), "findings": normalized[:10000], "count": len(normalized)}
    ev = root / "evidence"
    ev.mkdir(parents=True, exist_ok=True)
    atomic_write_json(ev / "external-findings-v39.json", data)
    return data


def build_ecosystem_matrix(root: str | Path, *, installed_tools: list[str] | None = None) -> dict[str, Any]:
    """Create a gap map between the platform and major open-source projects."""
    installed = set(installed_tools or [])
    rows = []
    for key, meta in ECOSYSTEMS.items():
        rows.append({
            "ecosystem": key,
            "projects": meta["projects"],
            "strengths": meta["strengths"],
            "integration_mode": meta["integration"],
            "installed_or_available": key in installed or any(p.lower() in {x.lower() for x in installed} for p in meta["projects"]),
            "platform_strategy": "reuse-specialist-capability-through-scoped-adapter; keep platform evidence, policy and reporting authoritative",
        })
    data = {
        "schema_version": VERSION,
        "status": "completed",
        "ecosystems": rows,
        "high_risk_exclusions": [
            "autonomous C2 operation",
            "payload generation",
            "credential theft/capture",
            "persistence deployment",
            "evasion/anti-detection features",
            "unbounded arbitrary command execution",
        ],
    }
    ev = Path(root) / "evidence"
    ev.mkdir(parents=True, exist_ok=True)
    atomic_write_json(ev / "ecosystem-integration-matrix-v39.json", data)
    return data
