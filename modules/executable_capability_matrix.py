#!/usr/bin/env python3
"""Executable capability matrix.

Distinguishes documented intent from what is actually importable/runnable
in this deployment. Does not claim engagement completeness.
"""

from __future__ import annotations

import importlib
import json
import shutil
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class Capability:
    id: str
    category: str
    description: str
    module: str | None
    tools: list[str]
    autonomy: str  # none | assisted | auto-safe
    human_required: bool
    status: str = "unknown"  # executable | partial | missing | human-led
    notes: str = ""


CORE = [
    Capability("recon-subdomains", "recon", "Subdomain discovery", "tool_executor", ["subfinder"], "auto-safe", False),
    Capability("recon-http", "recon", "HTTP probing", "tool_executor", ["httpx"], "auto-safe", False),
    Capability("recon-ports", "recon", "Port discovery", "tool_executor", ["naabu"], "auto-safe", False),
    Capability("recon-services", "recon", "Service enumeration", "tool_executor", ["nmap"], "auto-safe", False),
    Capability("web-crawl", "web", "Web crawling", "tool_executor", ["katana"], "auto-safe", False),
    Capability("vuln-candidates", "vuln", "Vulnerability candidate scanning", "tool_executor", ["nuclei"], "auto-safe", False),
    Capability("controlled-validation", "validation", "Bounded validation of candidates", "controlled_validation", [], "assisted", True),
    Capability("authorized-proofs", "exploitation", "Approval-gated bounded proof techniques", "authorized_exploitation_v31", [], "assisted", True),
    Capability("exploit-playbooks", "exploitation", "Human-led exploitation playbooks", "authorized_exploitation_v31", [], "assisted", True),
    Capability("adaptive-assessment", "intelligence", "Adaptive assessment planning", "adaptive_assessment_v28", [], "assisted", True),
    Capability("adaptive-investigation", "intelligence", "Persistent investigation loop", "adaptive_investigation_v29", [], "assisted", True),
    Capability("autonomy-controller", "autonomy", "Policy-bound autonomous loop", "autonomous_loop", [], "auto-safe", True),
    Capability("approval-queue", "autonomy", "Human approval for higher-risk actions", "approval_queue", [], "assisted", True),
    Capability("attack-graph", "intelligence", "Attack path hypotheses", "attack_graph", [], "assisted", True),
    Capability("ad-guidance", "identity", "AD methodology and command generation", "ad_advanced", ["nxc"], "assisted", True),
    Capability("credential-intel", "identity", "Credential intelligence (engagement-local)", "credential_intelligence_v19", [], "assisted", True),
    Capability("osint-engine", "osint", "Public-source OSINT orchestration", "osint_orchestrator_v233", [], "assisted", True),
    Capability("bounty-engine", "bounty", "Program-aware bug bounty planning", "bug_bounty_planner_v239", [], "assisted", True),
    Capability("aws-read-inventory", "cloud", "Read-only AWS inventory via allowlisted CLI", "tool_manager_v40", ["aws"], "assisted", True),
    Capability("redteam-support", "redteam", "Human-led red team support pack", "red_team_support_v30", [], "assisted", True),
    Capability("high-risk-controls", "redteam", "Operator-gated high-risk enablement (single-use)", "high_risk_controls_v32", [], "assisted", True),
    Capability("full-auto-exploit", "redteam", "Unrestricted automatic exploitation", None, [], "none", True),
    Capability("social-engineering", "redteam", "Social engineering operations", None, [], "none", True),
    Capability("physical-security", "redteam", "Physical intrusion testing", None, [], "none", True),
]


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def _module_importable(name: str | None) -> tuple[bool, str]:
    if not name:
        return False, "no-module"
    try:
        importlib.import_module(f"modules.{name}")
        return True, "ok"
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"


def evaluate() -> dict[str, Any]:
    rows = []
    for cap in CORE:
        mod_ok, mod_note = _module_importable(cap.module)
        tools_state = {t: _tool_available(t) for t in cap.tools}
        if cap.id in {"full-auto-exploit", "social-engineering", "physical-security"}:
            status = "human-led"
            notes = "Intentionally not automated by this platform"
        elif not mod_ok and cap.module:
            status = "missing"
            notes = mod_note
        elif cap.tools and not any(tools_state.values()):
            status = "partial"
            notes = "module present but required tools not installed in PATH"
        elif cap.tools and not all(tools_state.values()):
            status = "partial"
            notes = f"tools={tools_state}"
        elif mod_ok:
            status = "executable"
            notes = mod_note if not cap.tools else f"tools={tools_state}"
        else:
            status = "human-led"
            notes = "operator-driven capability"

        rows.append({
            **asdict(cap),
            "status": status,
            "notes": notes,
            "module_importable": mod_ok,
            "tools_available": tools_state,
        })

    summary = {
        "executable": sum(1 for r in rows if r["status"] == "executable"),
        "partial": sum(1 for r in rows if r["status"] == "partial"),
        "missing": sum(1 for r in rows if r["status"] == "missing"),
        "human_led": sum(1 for r in rows if r["status"] == "human-led"),
        "total": len(rows),
    }
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "version": "3.2.0",
        "summary": summary,
        "capabilities": rows,
        "disclaimer": (
            "Executable status means the component can run in this environment. "
            "It does not mean a complete penetration test or red team operation is automatic."
        ),
    }


def write_report(outdir: str | Path) -> Path:
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    data = evaluate()
    path = out / "executable-capability-matrix.json"
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    md = out / "executable-capability-matrix.md"
    lines = [
        "# Executable Capability Matrix",
        "",
        f"Generated: {data['generated_at']}",
        "",
        f"Summary: {data['summary']}",
        "",
        data["disclaimer"],
        "",
        "| ID | Category | Status | Autonomy | Human required | Notes |",
        "|----|----------|--------|----------|----------------|-------|",
    ]
    for r in data["capabilities"]:
        lines.append(
            f"| {r['id']} | {r['category']} | {r['status']} | {r['autonomy']} | {r['human_required']} | {r['notes'][:80]} |"
        )
    md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path
