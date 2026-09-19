"""V3.57 deterministic reasoning controller.

The controller is intentionally non-executing. It observes evidence, updates
canonical engagement state, ranks hypotheses, and emits a bounded next-task
projection. Actual tool execution remains in specialist engines and their
existing scope/authorization gates.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .engagement_state_v357 import EngagementState, VERSION
from .atomic_io import atomic_write_json

_SAFE_TASKS = {
    "recon": ("R1", 70.0),
    "web_crawl": ("R1", 68.0),
    "port_scan": ("R1", 65.0),
    "vulnerability_candidate_scan": ("R1", 66.0),
    "coverage_analysis": ("R0", 60.0),
    "evidence_correlation": ("R0", 62.0),
    "controlled_validation": ("R3", 58.0),
    "report_update": ("R0", 35.0),
}


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None


def _discover(root: Path) -> dict[str, Any]:
    ev = root / "evidence"
    files = sorted(ev.glob("*.json")) if ev.exists() else []
    statuses: list[dict[str, Any]] = []
    findings = 0
    for p in files:
        obj = _read_json(p)
        if isinstance(obj, dict):
            status = obj.get("status")
            if status:
                statuses.append({"artifact": p.name, "status": str(status)})
            for key in ("findings", "vulnerabilities", "hypotheses"):
                val = obj.get(key)
                if isinstance(val, list): findings += len(val)
        elif isinstance(obj, list):
            findings += len(obj)
    surfaces = {
        "recon": (root / "recon" / "subdomains.txt").is_file(),
        "live_http": (root / "recon" / "live-hosts.txt").is_file(),
        "ports": (root / "ports" / "naabu.txt").is_file() or (root / "ports" / "nmap-top.nmap").is_file(),
        "web": (root / "web" / "urls.txt").is_file(),
        "vulns": (root / "vulns" / "findings.json").is_file(),
    }
    return {"artifact_count": len(files), "findings": findings, "statuses": statuses, "surfaces": surfaces}


def _rank(root: Path, target: str, state: EngagementState, discovery: dict[str, Any]) -> list[dict[str, Any]]:
    s = discovery["surfaces"]
    tasks: list[dict[str, Any]] = []

    def add(action: str, reason: str, score: float, risk: str = "R1", approval: bool = False, basis: Any = ()):
        state.task(action=action, target=target, reason=reason, score=score, risk=risk,
                   status="approval_required" if approval else "planned", requires_approval=approval, basis=basis)
        tasks.append({"action": action, "target": target, "reason": reason, "score": score,
                      "risk": risk, "status": "approval_required" if approval else "planned",
                      "requires_approval": approval, "basis": list(basis) if isinstance(basis, (list, tuple)) else basis})

    if not s["recon"]:
        add("recon", "No normalized reconnaissance asset artifact exists.", 70.0, basis=["missing:recon"])
    elif not s["live_http"]:
        add("web_probe", "Recon exists but no live HTTP artifact exists.", 69.0, basis=["missing:live_http"])
    elif not s["web"]:
        add("web_crawl", "A live HTTP surface exists but no crawled URL artifact exists.", 68.0, basis=["missing:web"])
    if not s["ports"]:
        add("port_scan", "No port evidence is present for the current engagement state.", 64.0, basis=["missing:ports"])
    if s["web"] and not s["vulns"]:
        add("vulnerability_candidate_scan", "Web surface exists without vulnerability candidate evidence.", 66.0, basis=["web", "missing:vulns"])
    if discovery["findings"]:
        add("evidence_correlation", f"{discovery['findings']} finding/candidate records require correlation.", 63.0, risk="R0", basis=["finding_records"])
        add("controlled_validation", "Candidate evidence exists; validation is consequential and must remain approval-gated.", 61.0, risk="R3", approval=True, basis=["finding_records"])
    add("coverage_analysis", "Recompute evidence-backed coverage before declaring completion.", 55.0, risk="R0", basis=["coverage"])
    add("report_update", "Keep the evidence-backed report projection current.", 35.0, risk="R0", basis=["report"])
    return sorted(tasks, key=lambda x: (-x["score"], x["action"], x["target"]))[:12]


def build(root: str | Path, target: str, *, phase: str = "observation",
          authorized: bool = False) -> dict[str, Any]:
    root = Path(root)
    state = EngagementState(root)
    discovery = _discover(root)

    # Canonical observations are deliberately small and evidence-backed.
    for name, present in discovery["surfaces"].items():
        state.observation(kind="surface", source="reasoning-controller", artifact=name,
                          value={"present": present}, confidence=1.0)
    state.observation(kind="engagement", source="reasoning-controller",
                      value={"target": target, "phase": phase, "authorized": bool(authorized)}, confidence=1.0)
    state.episode(phase, "observed", discovery)

    # A hypothesis is a claim about what to investigate, never a finding.
    if discovery["surfaces"]["web"] and not discovery["surfaces"]["vulns"]:
        state.hypothesis(
            title="Web surface contains unvalidated security candidates",
            rationale="A crawled web surface exists but no vulnerability evidence artifact is present.",
            confidence=0.45, priority=66.0, basis=["web/urls.txt"],
        )
    if discovery["findings"]:
        state.hypothesis(
            title="Existing candidates require evidence correlation and validation",
            rationale="Finding-like records exist in the evidence corpus; they must be correlated and validated before reporting.",
            confidence=0.65, priority=72.0, basis=["evidence-json"],
        )

    tasks = _rank(root, target, state, discovery)
    snapshot = state.snapshot(limit=40)
    data = {
        "schema_version": VERSION,
        "controller": "observe -> persist -> hypothesize -> rank -> approval-gated action projection -> replan",
        "target": target,
        "phase": phase,
        "authorized_at_plan_time": bool(authorized),
        "execution": {"performed": False, "reason": "V3.57 controller is planning/state only"},
        "discovery": discovery,
        "next_tasks": tasks,
        "state_db": "state/engagement.db",
        "safety": {
            "no_scope_expansion": True,
            "no_authority_grant": True,
            "no_arbitrary_shell": True,
            "consequential_tasks_require_approval": True,
            "state_is_canonical": True,
        },
        "state_counts": {k: len(v) for k, v in snapshot.items() if isinstance(v, list)},
    }
    atomic_write_json(root / "evidence" / "reasoning-controller-v357.json", data)
    atomic_write_json(root / "evidence" / "reasoning-state-snapshot-v357.json", snapshot)
    return data
