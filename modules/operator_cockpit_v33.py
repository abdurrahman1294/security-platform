#!/usr/bin/env python3
"""Operator cockpit snapshot."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from modules.evidence_graph_v33 import EvidenceGraph
from modules.task_prioritizer import prioritize


def build_cockpit(outdir: str | Path, target: str = "") -> dict[str, Any]:
    root = Path(outdir)
    graph = EvidenceGraph(root)
    pending_approvals = []
    aq = root / "evidence" / "approval-queue.json"
    if aq.exists():
        try:
            pending_approvals = json.loads(aq.read_text(encoding="utf-8")).get("items") or []
            pending_approvals = [x for x in pending_approvals if x.get("status") == "pending"]
        except json.JSONDecodeError:
            pending_approvals = []

    hr = root / "evidence" / "high-risk-session.json"
    high_risk = {}
    if hr.exists():
        try:
            high_risk = json.loads(hr.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            high_risk = {}

    tasks = []
    try:
        tasks = [t.to_dict() for t in prioritize(root, target or "target")][:10]
    except Exception:
        tasks = []

    cockpit = {
        "target": target,
        "known": graph.summary(),
        "pending_approvals": pending_approvals,
        "high_risk": {
            "kill_switch": high_risk.get("kill_switch", False),
            "enabled_actions": high_risk.get("enabled_actions", []),
        },
        "next_tasks": tasks,
        "controls": {
            "pause_hint": "Use high-risk --kill-switch or stop the process",
            "approval_hint": "securityctl.py autonomy/high-risk approval flows",
        },
    }
    path = root / "evidence" / "operator-cockpit.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cockpit, indent=2), encoding="utf-8")

    md = root / "evidence" / "OPERATOR-COCKPIT.md"
    lines = [
        "# Operator Cockpit",
        "",
        f"Target: {target}",
        f"Graph nodes: {cockpit['known'].get('nodes')}",
        f"Pending approvals: {len(pending_approvals)}",
        f"Kill switch: {cockpit['high_risk'].get('kill_switch')}",
        "",
        "## Next tasks",
    ]
    for t in tasks:
        lines.append(f"- ({t.get('score')}) {t.get('action')} :: {t.get('target')}")
    md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return cockpit
