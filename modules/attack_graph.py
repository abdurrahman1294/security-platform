#!/usr/bin/env python3
"""Evidence-aware attack-path correlation for authorized assessments.

This module builds a *hypothesis graph* from observed findings. It does not
execute exploits, pivot, obtain credentials, or perform post-exploitation.
Every inferred edge is labelled with confidence and evidence so a tester can
manually validate or reject it.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from modules.findings_io import load_findings_file

SCHEMA_VERSION = "2.0"

# The capability-correlation and same-parent-domain passes below are O(n^2)
# over findings. That's fine for a typical engagement (tens to low
# hundreds of findings) but a large scope can produce thousands of nuclei
# results, and n^2 over a few thousand items is millions of comparisons.
# Cap how many findings feed those two passes; every finding still becomes
# a graph node, only the pairwise hypothesis correlation is capped.
MAX_CORRELATION_FINDINGS = 1500

SEVERITY_WEIGHT = {"critical": 1.0, "high": 0.85, "medium": 0.65, "low": 0.4, "info": 0.2}
STATUS_WEIGHT = {"confirmed": 1.0, "validated": 0.9, "validating": 0.75, "candidate": 0.65, "unreviewed": 0.6, "inconclusive": 0.45, "accepted-risk": 0.35, "blocked": 0.2, "false-positive": 0.0}

REVIEW_STATUSES = {"unreviewed", "candidate", "validating", "validated", "confirmed", "inconclusive", "blocked", "false-positive", "accepted-risk"}
EVIDENCE_WEIGHTS = {"scanner": 0.45, "reproducible": 0.70, "manual": 0.90, "confirmed": 1.0}

IMPACT_RULES = [
    ("confidentiality", ("secret", "credential", "password", "token", "api key", "data exposure", "disclosure")),
    ("integrity", ("rce", "command injection", "sql injection", "deserialization", "write access", "arbitrary file")),
    ("availability", ("denial of service", "dos", "resource exhaustion", "destructive")),
    ("account-control", ("auth bypass", "authentication bypass", "account takeover", "admin", "privilege escalation")),
]

REQUIRED_CAPABILITY_RULES = [
    ("credential-access", ("authenticated", "session", "cookie", "bearer", "jwt", "api key", "credential")),
    ("discovery", ("enumeration", "internal", "directory", "endpoint", "service")),
    ("privilege-escalation", ("admin", "root", "sudo", "privilege escalation")),
]

CAPABILITY_RULES = [
    ("initial-access", ("rce", "remote code execution", "command injection", "default login", "default credential", "auth bypass", "authentication bypass", "ssrf")),
    ("credential-access", ("credential", "password", "secret", "token", "jwt", "api key", "apikey", "session")),
    ("privilege-escalation", ("privilege escalation", "sudo", "setuid", "admin", "root", "elevation")),
    ("discovery", ("disclosure", "exposure", "directory listing", "information disclosure", "enumeration")),
    ("lateral-movement", ("smb", "winrm", "rdp", "ssh", "ldap", "active directory", "domain trust")),
    ("impact", ("deserialization", "ransomware", "denial of service", "data exposure", "data exfiltration", "destructive")),
]

@dataclass
class Node:
    id: str
    type: str
    label: str
    asset: str = ""
    finding_id: str = ""
    severity: str = "info"
    status: str = "unreviewed"
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

@dataclass
class Edge:
    source: str
    target: str
    relation: str
    status: str
    confidence: float
    rationale: str
    prerequisites: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)


def _text(f: dict[str, Any]) -> str:
    info = f.get("info") or {}
    vals = [
        info.get("name", ""), info.get("description", ""),
        " ".join(map(str, info.get("tags", []) or [])),
        f.get("template-id", ""), f.get("type", ""),
        f.get("matched-at", ""), f.get("host", ""),
    ]
    return " ".join(map(str, vals)).lower()


def _asset(f: dict[str, Any]) -> str:
    value = str(f.get("host") or f.get("matched-at") or "").strip()
    if not value:
        return "unknown-asset"
    parsed = urlparse(value if "://" in value else "//" + value)
    return (parsed.hostname or value.split("/", 1)[0]).lower().rstrip(".")


def _finding_id(f: dict[str, Any], index: int) -> str:
    supplied = f.get("finding_id") or f.get("id") or f.get("template-id")
    seed = "|".join([str(supplied or ""), _asset(f), str(f.get("matched-at") or ""), str(f.get("info", {}).get("name") or "")])
    digest = hashlib.sha256(seed.encode()).hexdigest()[:12]
    return f"F-{digest}" if digest else f"F-{index:04d}"


def _capabilities(f: dict[str, Any]) -> list[str]:
    text = _text(f)
    found = []
    for capability, needles in CAPABILITY_RULES:
        if any(n in text for n in needles):
            found.append(capability)
    return found


def _status(statuses: dict[str, Any], fid: str, finding: dict[str, Any] | None = None) -> str:
    keys = [fid]
    if finding:
        keys.extend([str(finding.get("finding_id") or ""), str(finding.get("id") or ""), str(finding.get("template-id") or "")])
    for key in keys:
        if key and key in statuses:
            return str((statuses.get(key) or {}).get("status") or "unreviewed").lower()
    return "unreviewed"


def _evidence_quality(f: dict[str, Any], status: str) -> float:
    """Estimate evidence quality without treating scanner output as proof."""
    if status == "confirmed":
        return 1.0
    info = f.get("info") or {}
    if any(f.get(k) for k in ("curl-command", "request", "response")):
        return EVIDENCE_WEIGHTS["reproducible"]
    if f.get("manual_validation") or "manual" in [str(x).lower() for x in (info.get("tags") or [])]:
        return EVIDENCE_WEIGHTS["manual"]
    return EVIDENCE_WEIGHTS["scanner"]

def _impacts(f: dict[str, Any]) -> list[str]:
    text = _text(f)
    return [impact for impact, needles in IMPACT_RULES if any(n in text for n in needles)]

def _required_capabilities(f: dict[str, Any]) -> list[str]:
    text = _text(f)
    return [cap for cap, needles in REQUIRED_CAPABILITY_RULES if any(n in text for n in needles)]

def _prerequisites(f: dict[str, Any], asset: str) -> list[str]:
    req = ["Finding must be manually validated", f"Asset `{asset}` must remain in authorized scope"]
    req.extend([f"Capability `{x}` must be established by evidence" for x in _required_capabilities(f)])
    return list(dict.fromkeys(req))

def _confidence(f: dict[str, Any], status: str) -> float:
    sev = str(f.get("info", {}).get("severity") or "info").lower()
    base = SEVERITY_WEIGHT.get(sev, 0.2)
    return round(base * STATUS_WEIGHT.get(status, 0.45), 2)


def load_findings(outdir: str | Path) -> list[dict[str, Any]]:
    root = Path(outdir)
    candidates = [
        root / "vulns" / "findings.json",
        root / "vulns" / "authenticated-findings.json",
        root / "api" / "api-findings.json",
        root / "servers" / "server-findings.json",
        root / "internal" / "internal-findings.json",
    ]
    findings = []
    seen = set()
    surface_names = {
        "findings.json": "web",
        "authenticated-findings.json": "authenticated-web",
        "api-findings.json": "api",
        "server-findings.json": "external-server",
        "internal-findings.json": "internal-network",
    }
    for path in candidates:
        for f in load_findings_file(path):
            fid = _finding_id(f, len(findings))
            if fid in seen:
                continue
            f["_graph_id"] = fid
            f["_graph_asset"] = _asset(f)
            f["_graph_surface"] = surface_names.get(path.name, path.parent.name)
            f["_graph_capabilities"] = _capabilities(f)
            seen.add(fid)
            findings.append(f)
    return findings


def load_statuses(outdir: str | Path) -> dict[str, Any]:
    path = Path(outdir) / "evidence" / "finding-status.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except json.JSONDecodeError:
        return {}


def build_attack_graph(outdir: str | Path) -> dict[str, Any]:
    root = Path(outdir)
    findings = load_findings(root)
    statuses = load_statuses(root)
    nodes: list[Node] = []
    edges: list[Edge] = []
    assets: dict[str, str] = {}
    capability_nodes: dict[str, str] = {}
    surface_nodes: dict[str, str] = {}

    for f in findings:
        fid = f["_graph_id"]
        asset = f["_graph_asset"]
        status = _status(statuses, fid, f)
        sev = str(f.get("info", {}).get("severity") or "info").lower()
        evidence = []
        for key in ("matched-at", "curl-command", "host"):
            value = f.get(key)
            if value:
                evidence.append(str(value)[:500])
        name = str(f.get("info", {}).get("name") or f.get("template-id") or fid)
        evidence_quality = _evidence_quality(f, status)
        confidence = round(min(1.0, _confidence(f, status) * (0.65 + 0.35 * evidence_quality)), 2)
        impacts = _impacts(f)
        required = _required_capabilities(f)
        prerequisites = _prerequisites(f, asset)
        refs = {
            "cwe": f.get("info", {}).get("classification", {}).get("cwe-id", []) if isinstance(f.get("info", {}).get("classification"), dict) else [],
            "cve": f.get("info", {}).get("classification", {}).get("cve-id", []) if isinstance(f.get("info", {}).get("classification"), dict) else [],
            "references": f.get("info", {}).get("reference", []) or [],
        }
        nodes.append(Node(fid, "finding", name, asset, fid, sev, status, confidence, evidence,
                          {"template_id": f.get("template-id", ""), "surface": f["_graph_surface"],
                           "capabilities_gained": f["_graph_capabilities"], "capabilities_required": required,
                           "impacts": impacts, "prerequisites": prerequisites, "evidence_quality": evidence_quality,
                           "references": refs}))
        surface = f["_graph_surface"]
        if surface not in surface_nodes:
            sid = "S-" + hashlib.sha256(surface.encode()).hexdigest()[:10]
            surface_nodes[surface] = sid
            nodes.append(Node(sid, "surface", surface.replace("-", " ").title(), confidence=1.0))
        edges.append(Edge(surface_nodes[surface], fid, "contains-finding", "observed", 1.0, "Finding originated from this assessment surface."))
        if asset not in assets:
            aid = "A-" + hashlib.sha256(asset.encode()).hexdigest()[:10]
            assets[asset] = aid
            nodes.append(Node(aid, "asset", asset, asset, confidence=1.0))
        edges.append(Edge(assets[asset], fid, "affected-by", "observed", 1.0, "Finding is associated with this observed asset."))
        for cap in f["_graph_capabilities"]:
            if cap not in capability_nodes:
                cid = "C-" + cap
                capability_nodes[cap] = cid
                nodes.append(Node(cid, "capability", cap.replace("-", " ").title(), asset, confidence=0.0))
            edges.append(Edge(fid, capability_nodes[cap], "may-provide", "hypothesis", _confidence(f, status),
                               f"Finding text/tags suggest the {cap} capability; manual validation is required.",
                               ["Validate the finding", "Confirm affected asset", "Record minimal evidence"]))

    # Correlate capabilities across findings/assets. These are hypotheses, never confirmed attack paths.
    correlation_pool = findings
    truncated_for_correlation = False
    if len(findings) > MAX_CORRELATION_FINDINGS:
        # Keep the highest-severity/highest-confidence findings for the
        # expensive pairwise passes; every finding is still a node above.
        correlation_pool = sorted(
            findings,
            key=lambda f: (SEVERITY_WEIGHT.get(str(f.get("info", {}).get("severity") or "info").lower(), 0.2)),
            reverse=True,
        )[:MAX_CORRELATION_FINDINGS]
        truncated_for_correlation = True

    for i, left in enumerate(correlation_pool):
        left_caps = set(left["_graph_capabilities"])
        if not left_caps:
            continue
        for right in correlation_pool[i + 1:]:
            right_caps = set(right["_graph_capabilities"])
            if not right_caps or left["_graph_asset"] == right["_graph_asset"]:
                continue
            bridge = None
            relation = None
            if "initial-access" in left_caps and ("credential-access" in right_caps or "discovery" in right_caps):
                bridge, relation = "initial-access-to-next-stage", "may-enable"
            elif "credential-access" in left_caps and "lateral-movement" in right_caps:
                bridge, relation = "credential-to-movement", "may-enable"
            elif "privilege-escalation" in left_caps and "impact" in right_caps:
                bridge, relation = "privilege-to-impact", "may-enable"
            elif "discovery" in left_caps and "lateral-movement" in right_caps:
                bridge, relation = "discovery-to-movement", "may-inform"
            if not bridge:
                continue
            s1 = _status(statuses, left["_graph_id"], left)
            s2 = _status(statuses, right["_graph_id"], right)
            confidence = round((_confidence(left, s1) + _confidence(right, s2)) / 2, 2)
            edges.append(Edge(left["_graph_id"], right["_graph_id"], relation, "hypothesis", confidence,
                              f"Potential cross-surface relationship: {bridge}. This is a correlation hypothesis, not proof of exploitability.",
                              ["Confirm both findings independently", "Verify trust/authorization prerequisites", "Do not assume credentials or access without evidence"],
                              [str(left.get("matched-at") or left.get("host") or "")[:300], str(right.get("matched-at") or right.get("host") or "")[:300]]))

    # Rank candidate finding-to-finding chains. Only explicit hypothesis edges are followed.
    finding_ids = {f["_graph_id"] for f in findings}
    adjacency: dict[str, list[Edge]] = {}
    for e in edges:
        if e.status == "hypothesis" and e.source in finding_ids and e.target in finding_ids:
            adjacency.setdefault(e.source, []).append(e)
    chains = []
    for start in adjacency:
        stack = [(start, [start], 0.0)]
        while stack:
            current, path, score = stack.pop()
            next_edges = adjacency.get(current, [])
            if not next_edges:
                if len(path) > 1:
                    chains.append({"nodes": path, "confidence": round(score / max(1, len(path) - 1), 2), "classification": "hypothesis"})
                continue
            for edge in next_edges:
                if edge.target in path or len(path) >= 6:
                    continue
                stack.append((edge.target, path + [edge.target], score + edge.confidence))
    chains.sort(key=lambda x: (-x["confidence"], -len(x["nodes"])))
    for chain in chains:
        chain["validation_state"] = "hypothesis"
        chain["next_safe_action"] = "Manually validate the next edge and record minimal evidence"

    # Trust relationships are deliberately conservative: hostname/domain similarity is
    # only a hypothesis and never establishes network reachability or trust.
    for i, left in enumerate(correlation_pool):
        for right in correlation_pool[i + 1:]:
            la, ra = left["_graph_asset"], right["_graph_asset"]
            if la == ra:
                continue
            lparts, rparts = la.split("."), ra.split(".")
            if len(lparts) >= 2 and len(rparts) >= 2 and ".".join(lparts[-2:]) == ".".join(rparts[-2:]):
                edges.append(Edge(left["_graph_id"], right["_graph_id"], "same-parent-domain", "hypothesis", 0.35,
                                  "Assets share a parent domain; this is only an inventory relationship, not proof of trust or reachability.",
                                  ["Verify DNS/network relationship", "Verify authorization and routing", "Do not assume cross-host access"]))

    # End-of-assessment nodes make the lifecycle explicit.
    lifecycle = [
        ("L-validate", "Validation", "Manually validate high-value hypotheses"),
        ("L-impact", "Impact Assessment", "Establish actual business/technical impact"),
        ("L-evidence", "Evidence", "Preserve minimal, redacted evidence"),
        ("L-remediate", "Remediation", "Recommend and track remediation"),
        ("L-retest", "Retest", "Verify remediation on an authorized retest"),
        ("L-report", "Final Reporting", "Produce technical and executive deliverables"),
    ]
    for nid, label, desc in lifecycle:
        nodes.append(Node(nid, "lifecycle", label, metadata={"description": desc}))
    for a, b in zip(lifecycle, lifecycle[1:]):
        edges.append(Edge(a[0], b[0], "workflow", "required", 1.0, "Professional assessment lifecycle step."))
    for f in findings:
        edges.append(Edge(f["_graph_id"], "L-validate", "requires-validation", "workflow", 1.0, "Automated findings require human validation before being treated as confirmed."))

    return {
        "schema_version": "2.0",
        "graph_type": "evidence-aware-attack-intelligence",
        "generated_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        "finding_count": len(findings),
        "nodes": [asdict(n) for n in nodes],
        "edges": [asdict(e) for e in edges],
        "candidate_chains": chains[:50],
        "notes": [
            "Hypothesis edges are not evidence of exploitability.",
            "Confirmed status must come from human review.",
            "The graph does not execute exploitation or post-exploitation actions.",
        ] + ([
            f"Pairwise correlation was limited to the top {MAX_CORRELATION_FINDINGS} findings "
            f"by severity (out of {len(findings)} total) to keep this run tractable; "
            "all findings are still present as nodes above."
        ] if truncated_for_correlation else []),
    }


def render_markdown(graph: dict[str, Any]) -> str:
    nodes = {n["id"]: n for n in graph["nodes"]}
    finding_nodes = [n for n in graph["nodes"] if n["type"] == "finding"]
    lines = ["# Evidence-Aware Attack Graph", "", f"Findings correlated: **{graph['finding_count']}**", "",
             "> This graph contains observed evidence and explicitly labelled hypotheses. It is a planning aid, not proof of exploitability and does not execute attacks.", ""]
    lines += ["## Surfaces", ""]
    surfaces = [n for n in graph["nodes"] if n["type"] == "surface"]
    lines.append("; ".join(f"**{n['label']}**" for n in surfaces) if surfaces else "No structured assessment surfaces were detected.")
    lines += ["", "## Findings", ""]
    if not finding_nodes:
        lines.append("No structured findings were available.")
    for n in finding_nodes:
        lines += [f"### {n['id']} — {n['label']}", f"- Asset: `{n['asset']}`", f"- Surface: `{n['metadata'].get('surface', 'unknown')}`", f"- Severity: `{n['severity']}`", f"- Review status: `{n['status']}`", f"- Confidence: `{n['confidence']}`", f"- Capabilities gained: {', '.join(n['metadata'].get('capabilities_gained', [])) or 'none'}", f"- Capabilities required: {', '.join(n['metadata'].get('capabilities_required', [])) or 'none'}", f"- Potential impacts: {', '.join(n['metadata'].get('impacts', [])) or 'none'}", f"- Evidence quality: `{n['metadata'].get('evidence_quality', 0)}`", ""]
    lines += ["## Candidate Chains", ""]
    chains = graph.get("candidate_chains", [])
    if not chains:
        lines.append("No multi-finding chains were inferred from the available evidence.")
    else:
        for i, chain in enumerate(chains[:20], 1):
            labels = [nodes.get(nid, {"label": nid})["label"] for nid in chain["nodes"]]
            lines.append(f"{i}. **" + " → ".join(labels) + f"** — confidence `{chain['confidence']}` (hypothesis)")
    lines += ["", "## Hypothesized Relationships", ""]
    hyps = [e for e in graph["edges"] if e["status"] == "hypothesis"]
    if not hyps:
        lines.append("No cross-finding hypotheses were generated.")
    for e in hyps:
        s = nodes.get(e["source"], {"label": e["source"]})
        t = nodes.get(e["target"], {"label": e["target"]})
        lines += [f"- **{s['label']}** → **{t['label']}** (`{e['relation']}`, confidence `{e['confidence']}`)", f"  - Rationale: {e['rationale']}", f"  - Prerequisites: {'; '.join(e['prerequisites'])}"]
    lines += ["", "## Mermaid Graph", "", "```mermaid", "flowchart TD"]
    for n in graph["nodes"]:
        label = re.sub(r"[\[\]\"`]", "", n["label"])[:80]
        lines.append(f"  {n['id']}[\"{label}\"]")
    for e in graph["edges"]:
        style = "==>" if e["status"] in ("observed", "required", "workflow") else "-.->"
        lines.append(f"  {e['source']} {style} {e['target']}")
    lines += ["```", "", "## Assessment Lifecycle", "", "Validation → Impact Assessment → Evidence → Remediation → Retest → Final Reporting", ""]
    return "\n".join(lines)


def generate_attack_graph(outdir: str | Path) -> tuple[Path, Path]:
    root = Path(outdir)
    evidence = root / "evidence"
    reports = root / "reports"
    evidence.mkdir(parents=True, exist_ok=True)
    reports.mkdir(parents=True, exist_ok=True)
    graph = build_attack_graph(root)
    json_path = evidence / "attack-graph.json"
    md_path = reports / "attack-graph.md"
    json_path.write_text(json.dumps(graph, indent=2), encoding="utf-8")
    md_path.write_text(render_markdown(graph), encoding="utf-8")
    return json_path, md_path
