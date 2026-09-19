#!/usr/bin/env python3
"""V39 mission orchestrator: durable task plan and engagement state.

This module plans and tracks an authorized assessment. It does not contain exploit
logic; consequential proof remains behind the existing V30-V38 controls.
"""
from __future__ import annotations
import json, uuid
from .atomic_io import load_json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

PHASES = ["authorization", "recon", "enumeration", "web", "vuln_scan", "api", "servers", "internal", "ad", "intelligence", "proof", "report"]

@dataclass
class Task:
    task_id: str
    phase: str
    action: str
    status: str = "pending"
    priority: int = 50
    depends_on: list[str] | None = None
    reason: str = ""
    attempts: int = 0
    started: str = ""
    finished: str = ""
    result: str = ""

    def __post_init__(self):
        if self.depends_on is None:
            self.depends_on = []

class MissionState:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.path = self.root / "evidence" / "mission-state-v39.json"
        self.root.joinpath("evidence").mkdir(parents=True, exist_ok=True)
        self.data = self._load()

    def _load(self):
        if self.path.exists():
            data = load_json(self.path, None)
            if isinstance(data, dict): return data
        return {"schema_version":"39.0", "mission_id":f"MSN-{uuid.uuid4().hex[:10]}",
                "status":"created", "created":datetime.now(timezone.utc).isoformat(),
                "updated":"", "tasks":[], "decisions":[]}

    def save(self):
        self.data["updated"] = datetime.now(timezone.utc).isoformat()
        self.path.write_text(json.dumps(self.data, indent=2), encoding="utf-8")
        return self.path

def build_plan(root: str | Path, *, full=True, include_internal=False, include_ad=False):
    state = MissionState(root)
    existing = {t.get("action") for t in state.data.get("tasks", [])}
    desired = [
        ("authorization", "verify-authorization", 100, [], "Gate the mission before active testing."),
        ("recon", "external-recon", 95, ["verify-authorization"], "Discover in-scope assets."),
        ("enumeration", "port-and-service-enumeration", 90, ["external-recon"], "Map exposed services."),
        ("web", "web-enumeration", 88, ["external-recon"], "Map live web applications and endpoints."),
        ("vuln_scan", "vulnerability-discovery", 85, ["web", "port-and-service-enumeration"], "Identify candidate weaknesses."),
        ("api", "api-assessment", 80, ["web", "vulnerability-discovery"], "Assess discovered API surfaces."),
        ("servers", "server-assessment", 78, ["port-and-service-enumeration"], "Assess externally exposed servers."),
        ("intelligence", "correlate-and-prioritize", 75, ["vulnerability-discovery"], "Normalize, correlate and prioritize evidence."),
        ("proof", "controlled-proof-review", 70, ["correlate-and-prioritize"], "Prepare operator-approved proof candidates; never auto-exploit."),
        ("report", "report-pack", 60, ["correlate-and-prioritize", "controlled-proof-review"], "Produce the engagement deliverables."),
    ]
    if include_internal:
        desired.insert(7, ("internal", "internal-assessment", 77, ["verify-authorization"], "Assess explicitly authorized internal scope."))
    if include_ad:
        desired.insert(8, ("ad", "active-directory-assessment", 76, ["verify-authorization"], "Generate and run safe AD enumeration guidance."))
    if not full:
        desired = [x for x in desired if x[0] in {"authorization", "recon", "enumeration", "web", "vuln_scan", "intelligence", "proof", "report"}]
    tasks = list(state.data.get("tasks", []))
    for phase, action, priority, deps, reason in desired:
        if action not in existing:
            tasks.append(asdict(Task(f"TSK-{uuid.uuid4().hex[:8]}", phase, action, priority=priority, depends_on=deps, reason=reason)))
    state.data["tasks"] = tasks
    state.data["status"] = "planned"
    state.save()
    return state.path

def load(root):
    return MissionState(root).data

def mark(root, action, status, result=""):
    state = MissionState(root)
    now = datetime.now(timezone.utc).isoformat()
    for task in state.data.get("tasks", []):
        if task.get("action") == action:
            task["status"] = status
            task["result"] = result
            task["attempts"] = int(task.get("attempts", 0)) + (1 if status in {"running", "failed", "completed"} else 0)
            if status == "running": task["started"] = now
            if status in {"completed", "failed", "blocked"}: task["finished"] = now
            break
    state.save(); return state.path

def next_ready(root):
    data = load(root)
    done = {t["action"] for t in data.get("tasks", []) if t.get("status") == "completed"}
    candidates=[]
    for t in data.get("tasks", []):
        if t.get("status") != "pending": continue
        if all(dep in done for dep in t.get("depends_on", [])):
            candidates.append(t)
    return sorted(candidates, key=lambda x: (-int(x.get("priority",50)), x.get("task_id","")))
