"""V5.3 Unified Security Core

Adds verified gaps vs PentestGPT / HexStrike / (ethical analogues of) Xanthorox
without duplicating existing fusion/depth/pentest engines.

NOT included: malware generation, real-world phishing kits, unrestricted exploit
chains, or anything that bypasses authorization/scope.
"""
from __future__ import annotations

import hashlib
import json
import re
import struct
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any, Iterable

VERSION = "5.3.0"


def _dump(path: Path, obj: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, default=str), encoding="utf-8")
    return path


def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# 1) Capability audit (machine-readable)
# ---------------------------------------------------------------------------

AUDIT_ROWS = [
    # capability, ours, pentestgpt, hexstrike, xanthorox_note, action
    ("autonomous_planning", "yes", "yes", "yes", "partial", "keep_upgrade_v53_mission_loop"),
    ("persistent_assessment_state", "yes", "yes", "yes", "partial", "keep"),
    ("recon", "yes", "yes", "yes", "yes", "keep"),
    ("web_testing", "partial", "yes", "yes", "no", "upgrade_v53_web_advanced"),
    ("api_testing", "yes", "partial", "yes", "no", "keep"),
    ("browser_automation", "no", "partial", "yes", "no", "add_v53"),
    ("osint", "yes", "no", "yes", "yes", "keep_upgrade_correlation"),
    ("exploit_validation", "partial", "yes", "yes", "no", "upgrade_lab_validation"),
    ("privilege_escalation", "partial", "yes", "yes", "no", "upgrade_adversary_emu"),
    ("cloud", "partial", "no", "yes", "no", "keep_existing_cloud"),
    ("mobile_security_lab", "partial", "no", "partial", "no", "keep_existing_mobile"),
    ("malware_analysis", "no", "no", "partial", "yes_offensive", "add_static_lab_only"),
    ("phishing_simulation", "no", "no", "no", "yes_offensive", "add_safe_training_only"),
    ("social_engineering_simulation", "no", "no", "no", "yes_offensive", "add_safe_training_only"),
    ("adversary_emulation", "partial", "partial", "partial", "yes", "upgrade_v53"),
    ("tool_orchestration", "partial", "partial", "yes", "partial", "keep_depth_v52_adapters"),
    ("mcp_tool_bridge", "partial", "no", "yes", "partial", "keep_governed_mcp"),
    ("attack_path_graph", "partial", "partial", "partial", "partial", "upgrade_v53"),
    ("reporting", "yes", "yes", "yes", "no", "keep"),
    ("authorization_roe", "yes", "partial", "partial", "no", "keep_strengthen"),
    ("malware_generation", "no", "no", "no", "yes", "refuse"),
    ("uncensored_criminal_assist", "no", "no", "no", "yes", "refuse"),
]


def build_capability_audit(output: Path) -> dict:
    rows = []
    for cap, ours, pg, hx, xa, action in AUDIT_ROWS:
        rows.append({
            "capability": cap,
            "engine_now": ours,
            "pentestgpt": pg,
            "hexstrike": hx,
            "xanthorox": xa,
            "action": action,
        })
    report = {
        "schema_version": VERSION,
        "generated_at": time.time(),
        "rows": rows,
        "summary": {
            "keep": sum(1 for r in rows if r["action"].startswith("keep")),
            "upgrade_or_add": sum(1 for r in rows if r["action"].startswith(("upgrade", "add"))),
            "refuse": sum(1 for r in rows if r["action"] == "refuse"),
        },
        "notes": [
            "Xanthorox offensive generation capabilities are refused.",
            "Browser automation is bounded HTTP snapshot (+ optional playwright if installed).",
            "Malware module is static analysis lab only.",
            "Phishing module is authorized awareness simulation only.",
        ],
    }
    _dump(Path(output) / "evidence" / "capability-audit-v530.json", report)
    # also markdown table
    md = ["# Capability Audit V5.3", "",
          "| Capability | Engine | PentestGPT | HexStrike | Xanthorox | Action |",
          "|---|---|---|---|---|---|"]
    for r in rows:
        md.append(f"| {r['capability']} | {r['engine_now']} | {r['pentestgpt']} | {r['hexstrike']} | {r['xanthorox']} | {r['action']} |")
    md_path = Path(output) / "reports" / "CAPABILITY_AUDIT_V530.md"
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text("\n".join(md) + "\n", encoding="utf-8")
    report["markdown"] = str(md_path)
    return report


# ---------------------------------------------------------------------------
# 2) Browser automation lab (bounded)
# ---------------------------------------------------------------------------

def browser_snapshot(output: Path, url: str, *, authorized: bool, scope_hosts: set[str] | None = None) -> dict:
    """Fetch URL metadata for in-scope targets. Optional playwright screenshot if available."""
    if not authorized:
        return {"status": "denied", "reason": "authorization-required"}
    try:
        host = urllib.parse.urlsplit(url).hostname or ""
    except Exception:
        return {"status": "denied", "reason": "bad-url"}
    if scope_hosts is not None and host not in scope_hosts and not any(host.endswith(h.lstrip("*")) for h in scope_hosts if h.startswith("*.")):
        # allow if exact or empty scope means caller already checked
        if scope_hosts and host not in scope_hosts:
            return {"status": "denied", "reason": "out-of-scope", "host": host}
    result = {"schema_version": VERSION, "url": url, "host": host, "status": "error"}
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SecurityPlatform-BrowserLab/5.3"}, method="GET")
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read(64_000)
            result.update({
                "status": "ok",
                "http_status": getattr(resp, "status", None),
                "content_type": resp.headers.get("Content-Type", ""),
                "title": (re.search(rb"<title[^>]*>(.*?)</title>", body, re.I | re.S).group(1).decode("utf-8", "replace")[:200]
                          if re.search(rb"<title[^>]*>(.*?)</title>", body, re.I | re.S) else ""),
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "bytes": len(body),
            })
    except Exception as e:
        result["error"] = str(e)[:300]
    # optional playwright
    try:
        from playwright.sync_api import sync_playwright  # type: ignore
        shot = Path(output) / "evidence" / "browser" / f"shot-{hashlib.sha256(url.encode()).hexdigest()[:12]}.png"
        shot.parent.mkdir(parents=True, exist_ok=True)
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, timeout=15000)
            page.screenshot(path=str(shot), full_page=False)
            browser.close()
        result["screenshot"] = str(shot)
        result["browser_engine"] = "playwright"
    except Exception:
        result["browser_engine"] = "http-only"
    _dump(Path(output) / "evidence" / "browser-snapshot-v530.json", result)
    return result


# ---------------------------------------------------------------------------
# 3) Static malware analysis lab (defensive)
# ---------------------------------------------------------------------------

def malware_static_lab(output: Path, sample: Path) -> dict:
    sample = Path(sample)
    if not sample.is_file():
        return {"status": "error", "error": "sample-missing"}
    data = sample.read_bytes()[:8_000_000]
    full_hash = hashlib.sha256(sample.read_bytes()).hexdigest() if sample.stat().st_size <= 32_000_000 else hashlib.sha256(data).hexdigest()
    magic = data[:4]
    file_type = "unknown"
    if data[:2] == b"MZ":
        file_type = "pe"
    elif data[:4] == b"\x7fELF":
        file_type = "elf"
    elif data[:2] == b"PK":
        file_type = "zip-or-office-or-apk"
    elif data[:4] == b"%PDF":
        file_type = "pdf"
    # strings
    strings = re.findall(rb"[\x20-\x7e]{6,120}", data)
    interesting = []
    markers = (b"http://", b"https://", b"cmd.exe", b"powershell", b"/bin/sh", b"socket", b"CreateRemoteThread", b"VirtualAlloc")
    for s in strings[:5000]:
        low = s.lower()
        if any(m.lower() in low for m in markers) or b"http" in low:
            interesting.append(s.decode("utf-8", "replace")[:120])
        if len(interesting) >= 40:
            break
    report = {
        "schema_version": VERSION,
        "status": "completed",
        "sample": str(sample),
        "size": sample.stat().st_size,
        "sha256": full_hash,
        "md5": hashlib.md5(data[: min(len(data), 8_000_000)]).hexdigest(),
        "file_type_guess": file_type,
        "interesting_strings": interesting,
        "note": "Static lab only — no detonation sandbox in this module.",
        "lab_only": True,
    }
    _dump(Path(output) / "evidence" / "malware-static-v530.json", report)
    return report


# ---------------------------------------------------------------------------
# 4) Safe phishing / SE simulation (training)
# ---------------------------------------------------------------------------

def phishing_simulation_plan(output: Path, org: str, scenario: str = "credential-awareness") -> dict:
    """Authorized awareness simulation blueprint — no live mail send, no credential capture store."""
    plan = {
        "schema_version": VERSION,
        "status": "planned",
        "organization": org,
        "scenario": scenario,
        "stages": [
            {"id": "approve", "name": "Written authorization & ROE", "required": True},
            {"id": "audience", "name": "Define internal audience only", "required": True},
            {"id": "template", "name": "Training message template (non-credential-harvesting)"},
            {"id": "landing", "name": "Internal training landing page (explains simulation)"},
            {"id": "metrics", "name": "Measure report-rate / time-to-report (not password capture)"},
            {"id": "debrief", "name": "Awareness debrief report"},
        ],
        "forbidden": [
            "real credential harvesting",
            "third-party targeting without contract",
            "malware attachments",
            "smishing to public numbers without authorization",
        ],
        "metrics": ["emails_sent", "emails_reported", "time_to_first_report", "training_completion"],
        "note": "Simulation blueprint for authorized security awareness programs only.",
    }
    _dump(Path(output) / "evidence" / "phishing-sim-plan-v530.json", plan)
    return plan


# ---------------------------------------------------------------------------
# 5) Adversary emulation (lab / authorized)
# ---------------------------------------------------------------------------

EMULATION_STAGES = [
    ("recon", "TA0043", "Discover authorized surface"),
    ("initial_access", "TA0001", "Simulate initial access path in lab"),
    ("execution", "TA0002", "Validate execution hypothesis in lab"),
    ("persistence", "TA0003", "Lab persistence markers only"),
    ("privilege_escalation", "TA0004", "Lab privilege path validation"),
    ("discovery", "TA0007", "Host/network discovery in scope"),
    ("lateral_movement", "TA0008", "Lab lateral auth simulation"),
    ("collection", "TA0009", "Identify sensitive data locations in lab"),
    ("reporting", "TA9999", "Detection & findings report"),
]


def adversary_emulation_plan(output: Path, target: str) -> dict:
    stages = []
    for sid, tactic, desc in EMULATION_STAGES:
        stages.append({
            "stage": sid,
            "mitre_tactic": tactic,
            "description": desc,
            "status": "planned",
            "requires_authorization": True,
            "lab_preferred": True,
        })
    plan = {
        "schema_version": VERSION,
        "target": target,
        "stages": stages,
        "note": "Plan only — execution uses existing remote/attack-chain/depth adapters under ROE.",
    }
    _dump(Path(output) / "evidence" / "adversary-emulation-plan-v530.json", plan)
    return plan


def adversary_emulation_run_dry(output: Path, target: str) -> dict:
    plan = adversary_emulation_plan(output, target)
    results = []
    for st in plan["stages"]:
        results.append({
            "stage": st["stage"],
            "mitre_tactic": st["mitre_tactic"],
            "status": "dry_run",
            "evidence": f"stage-{st['stage']}-planned",
        })
    out = {"schema_version": VERSION, "target": target, "results": results, "mode": "dry_run"}
    _dump(Path(output) / "evidence" / "adversary-emulation-run-v530.json", out)
    return out


# ---------------------------------------------------------------------------
# 6) Attack-path graph from findings
# ---------------------------------------------------------------------------

def build_attack_path_graph(output: Path, findings: list[dict], target: str) -> dict:
    nodes = [{"id": "target", "label": target, "type": "asset"}]
    edges = []
    for i, f in enumerate(findings[:100]):
        nid = f"f{i}"
        label = f.get("name") or f.get("summary") or f.get("template") or f.get("service") or f.get("source") or "finding"
        sev = str(f.get("severity") or "info").lower()
        nodes.append({"id": nid, "label": str(label)[:80], "type": "finding", "severity": sev, "source": f.get("source")})
        edges.append({"from": "target", "to": nid, "relation": "exposes"})
        # chain heuristics
        if sev in ("critical", "high") and f.get("source") in ("nuclei", "sqlmap"):
            nodes.append({"id": f"v{i}", "label": "validation_candidate", "type": "hypothesis"})
            edges.append({"from": nid, "to": f"v{i}", "relation": "suggests_validation"})
        if f.get("port") or f.get("service"):
            nodes.append({"id": f"s{i}", "label": f"service:{f.get('service') or f.get('port')}", "type": "service"})
            edges.append({"from": nid, "to": f"s{i}", "relation": "service"})
    graph = {
        "schema_version": VERSION,
        "target": target,
        "nodes": nodes,
        "edges": edges,
        "node_count": len(nodes),
        "edge_count": len(edges),
    }
    _dump(Path(output) / "evidence" / "attack-path-graph-v530.json", graph)
    return graph


# ---------------------------------------------------------------------------
# 7) Advanced web checks (safe / passive-leaning)
# ---------------------------------------------------------------------------

def web_advanced_passive(output: Path, url: str, *, authorized: bool) -> dict:
    if not authorized:
        return {"status": "denied", "reason": "authorization-required"}
    checks = []
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SecurityPlatform-WebAdv/5.3"}, method="GET")
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read(128_000)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            text = body.decode("utf-8", "replace")
    except Exception as e:
        return {"status": "error", "error": str(e)[:300]}

    # security headers
    for h in ("content-security-policy", "x-frame-options", "x-content-type-options", "strict-transport-security"):
        checks.append({"check": f"header:{h}", "present": h in headers, "severity": "low" if h not in headers else "info"})
    # jwt in body/cookies (structure only)
    jwt_re = re.findall(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", text)
    if jwt_re:
        checks.append({"check": "jwt_like_token_observed", "count": len(jwt_re), "severity": "info", "note": "structure only — not cracked"})
    # graphql hint
    if "graphql" in text.lower() or "/graphql" in text.lower():
        checks.append({"check": "graphql_hint", "severity": "info"})
    # forms
    forms = len(re.findall(r"<form", text, re.I))
    checks.append({"check": "html_forms", "count": forms, "severity": "info"})
    # reflected query param crude (only if URL has query)
    qs = urllib.parse.urlsplit(url).query
    if qs:
        for k, v in urllib.parse.parse_qsl(qs):
            if v and v in text:
                checks.append({"check": "reflected_param", "param": k, "severity": "medium", "note": "possible reflection — needs manual validation"})
    report = {"schema_version": VERSION, "url": url, "status": "completed", "checks": checks}
    _dump(Path(output) / "evidence" / "web-advanced-v530.json", report)
    return report


# ---------------------------------------------------------------------------
# 8) Autonomous mission loop (orchestrator brain)
# ---------------------------------------------------------------------------

def autonomous_mission_loop(
    output: Path,
    target: str,
    *,
    authorized: bool,
    objective: str = "authorized assessment",
    max_steps: int = 6,
) -> dict:
    """Objective → plan → act(dry/adapter) → correlate → adapt → report state."""
    if not authorized:
        return {"status": "denied", "reason": "authorization-required"}
    output = Path(output)
    steps = []
    state = {"findings": [], "graph": None, "proposals": []}

    # step 1 audit
    steps.append({"step": 1, "action": "capability_audit", "result": "ok"})
    build_capability_audit(output)

    # step 2 adversary plan
    emu = adversary_emulation_plan(output, target)
    steps.append({"step": 2, "action": "adversary_plan", "stages": len(emu["stages"])})

    # step 3 web passive if URL-like
    if target.startswith("http"):
        web = web_advanced_passive(output, target, authorized=True)
        steps.append({"step": 3, "action": "web_advanced_passive", "status": web.get("status")})
        # convert checks to findings-ish
        for c in web.get("checks") or []:
            if c.get("severity") in ("medium", "high", "critical") or c.get("check") == "reflected_param":
                state["findings"].append({"source": "web-advanced", **c})
    else:
        steps.append({"step": 3, "action": "web_advanced_passive", "status": "skipped_non_url"})

    # step 4 browser snapshot if URL
    if target.startswith("http"):
        br = browser_snapshot(output, target, authorized=True, scope_hosts=None)
        steps.append({"step": 4, "action": "browser_snapshot", "status": br.get("status")})
    else:
        steps.append({"step": 4, "action": "browser_snapshot", "status": "skipped_non_url"})

    # step 5 attack graph
    graph = build_attack_path_graph(output, state["findings"], target)
    state["graph"] = {"nodes": graph["node_count"], "edges": graph["edge_count"]}
    steps.append({"step": 5, "action": "attack_path_graph", **state["graph"]})

    # step 6 supervisor proposals via depth if available
    try:
        from modules.capability_depth_v520 import LLMSupervisor
        prop = LLMSupervisor(output).propose(target, {"findings": state["findings"]})
        state["proposals"] = prop.get("proposals") or []
        steps.append({"step": 6, "action": "supervisor_propose", "count": len(state["proposals"])})
    except Exception as e:
        steps.append({"step": 6, "action": "supervisor_propose", "status": "error", "error": str(e)[:120]})

    # truncate to max_steps representation
    mission = {
        "schema_version": VERSION,
        "status": "completed",
        "target": target,
        "objective": objective,
        "steps": steps[:max_steps],
        "findings_count": len(state["findings"]),
        "graph": state["graph"],
        "proposals": state["proposals"][:10],
        "next_operator_actions": [
            "Review attack-path-graph-v530.json",
            "Run depth-v52 adapters under scope for validated tools",
            "Import tool outputs and retest snapshots",
            "Generate executive report via depth-v52 --action report",
        ],
    }
    _dump(output / "evidence" / "autonomous-mission-v530.json", mission)
    return mission


# ---------------------------------------------------------------------------
# 9) Unified command-center model (UI data)
# ---------------------------------------------------------------------------

def command_center_model(output: Path) -> dict:
    model = {
        "schema_version": VERSION,
        "title": "Security Command",
        "missions": [
            {"id": "auto-pentest", "label": "Autonomous Pentest", "cli": "unified-v53 --action mission"},
            {"id": "recon-osint", "label": "Recon / OSINT", "cli": "osint"},
            {"id": "web-api", "label": "Web / API", "cli": "pentest --phases web,api"},
            {"id": "network", "label": "Network", "cli": "depth-v52 --action run-adapter --tool nmap"},
            {"id": "cloud", "label": "Cloud", "cli": "cloud"},
            {"id": "mobile", "label": "Mobile", "cli": "mobile"},
            {"id": "malware-lab", "label": "Malware Lab (static)", "cli": "unified-v53 --action malware-static"},
            {"id": "adversary", "label": "Adversary Simulation", "cli": "unified-v53 --action adversary"},
            {"id": "phishing-sim", "label": "Awareness Simulation", "cli": "unified-v53 --action phishing-sim"},
            {"id": "reports", "label": "Reports", "cli": "depth-v52 --action report"},
        ],
        "panels": ["Missions", "Evidence", "Findings", "Attack Graph", "Reports", "Authorization"],
    }
    _dump(Path(output) / "evidence" / "command-center-v530.json", model)
    return model


# ---------------------------------------------------------------------------
# Facade
# ---------------------------------------------------------------------------

class UnifiedCoreV53:
    def __init__(self, output: str | Path):
        self.output = Path(output)

    def audit(self) -> dict:
        return build_capability_audit(self.output)

    def mission(self, target: str, authorized: bool, objective: str = "authorized assessment") -> dict:
        return autonomous_mission_loop(self.output, target, authorized=authorized, objective=objective)

    def browser(self, url: str, authorized: bool) -> dict:
        return browser_snapshot(self.output, url, authorized=authorized)

    def malware_static(self, sample: str) -> dict:
        return malware_static_lab(self.output, Path(sample))

    def phishing_sim(self, org: str, scenario: str = "credential-awareness") -> dict:
        return phishing_simulation_plan(self.output, org, scenario)

    def adversary(self, target: str, execute_dry: bool = True) -> dict:
        return adversary_emulation_run_dry(self.output, target) if execute_dry else adversary_emulation_plan(self.output, target)

    def attack_graph(self, target: str) -> dict:
        findings = []
        for name in ("imported-findings-v520.json", "imported-findings-v510.json", "web-advanced-v530.json"):
            data = _load(self.output / "evidence" / name)
            if not data:
                continue
            if isinstance(data, dict) and "findings" in data:
                findings.extend(data.get("findings") or [])
            elif isinstance(data, dict) and "checks" in data:
                findings.extend(data.get("checks") or [])
        return build_attack_path_graph(self.output, findings, target)

    def web_advanced(self, url: str, authorized: bool) -> dict:
        return web_advanced_passive(self.output, url, authorized=authorized)

    def command_center(self) -> dict:
        return command_center_model(self.output)

    def status(self) -> dict:
        return {
            "schema_version": VERSION,
            "modules": [
                "capability_audit", "browser_lab", "malware_static_lab",
                "phishing_sim_safe", "adversary_emulation", "attack_path_graph",
                "web_advanced_passive", "autonomous_mission_loop", "command_center",
            ],
            "refused": ["malware_generation", "uncensored_criminal_assist", "live_credential_harvesting"],
        }
