from __future__ import annotations
"""V3.13 governed mission execution and workflow-coverage fabric.

This layer turns the V3.12 evidence-driven plan into an explicit, auditable
execution contract. It does not add a new bypass around ToolManager or scope
policy. Active steps require authorization, in-scope validation, and a
single-use operator approval token tied to the exact action and target.
"""
import json
import time
from pathlib import Path
from typing import Any

from modules.atomic_io import atomic_write_json
from modules.approval_queue import ApprovalQueue
from modules.autonomy_policy import AutonomyPolicy, RiskClass

VERSION = "3.13.0"

# High-level workflow coverage derived from current official Metasploit and
# Cobalt Strike product/documentation concepts. Dangerous implementation
# primitives remain outside this fabric and are represented as gaps/externals.
WORKFLOW_COVERAGE = {
    "reconnaissance": {"status": "implemented", "composition": ["subdomain_enum", "http_probe", "port_scan", "service_enum"]},
    "vulnerability_discovery": {"status": "implemented", "composition": ["vuln_candidate_scan", "web_crawl", "source_import"]},
    "module_or_capability_registry": {"status": "implemented", "composition": ["tool_inventory", "ecosystem_matrix", "capability_fusion"]},
    "session_and_evidence_state": {"status": "implemented", "composition": ["evidence_ledger", "execution_ledger", "approval_queue", "artifact_provenance"]},
    "read_only_post_compromise_analysis": {"status": "implemented_or_imported", "composition": ["identity", "network", "cloud", "mobile", "source"]},
    "operator_tasking": {"status": "implemented", "composition": ["adaptive_mission", "approval_queue", "single_use_tokens"]},
    "attack_path_reasoning": {"status": "implemented", "composition": ["correlation", "adaptive_replan", "capability_fusion"]},
    "detection_validation": {"status": "implemented_or_lab", "composition": ["controlled_validation", "ATT&CK_metadata", "retest_queue"]},
    "reporting_and_timeline": {"status": "implemented", "composition": ["evidence", "reports", "execution_ledger"]},
    "team_collaboration": {"status": "partial", "composition": ["durable_artifacts", "audit_ledger", "exportable_state"]},
    "payload_generation_and_c2": {"status": "external_specialist_required", "reason": "requires a dedicated operator-controlled red-team platform; not reproduced here"},
    "stealth_and_evasion": {"status": "external_specialist_required", "reason": "not automatically implemented; detection validation remains the safe objective"},
    "credential_capture_or_theft": {"status": "governed_external_or_lab_only", "reason": "no automated capture/theft primitive"},
    "persistence_deployment": {"status": "governed_external_or_lab_only", "reason": "no automatic persistence deployment"},
    "destructive_actions": {"status": "denied", "reason": "outside the execution fabric"},
}

SPECIALIST_ACTIONS = {
    "recon": ["subdomain_enum", "http_probe", "port_scan"],
    "web": ["web_crawl", "vuln_candidate_scan"],
    "network": ["service_enum"],
    "identity": ["ad_read_enum"],
    "cloud": ["cloud_read_inventory"],
    "mobile": ["normalize_assets"],
    "source": ["normalize_assets"],
    "correlator": ["coverage_analysis", "prioritize_tasks"],
    "validator": ["controlled_validation"],
    "reporter": ["draft_report"],
}

ACTIVE_ACTIONS = {x for values in SPECIALIST_ACTIONS.values() for x in values if x not in {
    "normalize_assets", "coverage_analysis", "prioritize_tasks", "draft_report"
}}


def _write(root: Path, name: str, data: dict[str, Any]) -> dict[str, Any]:
    root.joinpath("evidence").mkdir(parents=True, exist_ok=True)
    atomic_write_json(root / "evidence" / name, data)
    return data


def build_workflow_coverage(root: str | Path) -> dict[str, Any]:
    root = Path(root)
    gaps = [k for k, v in WORKFLOW_COVERAGE.items() if v.get("status") not in {"implemented", "implemented_or_imported", "implemented_or_lab", "partial"}]
    data = {
        "schema_version": VERSION,
        "component": "governed-mission-fabric",
        "coverage": WORKFLOW_COVERAGE,
        "gaps": gaps,
        "principle": "workflow coverage is composed from registered capabilities; composition never grants authority",
        "approval_model": "authorization + scope + exact-action single-use approval",
    }
    return _write(root, "workflow-coverage-v313.json", data)


def _adaptive_plan(root: Path, target: str, objective: str, max_steps: int, authorized: bool) -> dict[str, Any]:
    from modules.adaptive_mission_controller_v312 import build_adaptive_mission
    return build_adaptive_mission(root, target, objective, max_steps, authorized)


def build_governed_execution_plan(root: str | Path, target: str, objective: str = "general", max_steps: int = 8) -> dict[str, Any]:
    root = Path(root)
    mission = _adaptive_plan(root, target, objective, max_steps, authorized=False)
    steps = []
    for step in mission.get("steps", []):
        role = str(step.get("specialist"))
        for action in SPECIALIST_ACTIONS.get(role, []):
            risk = AutonomyPolicy().risk_for(action).value
            steps.append({
                "step": len(steps) + 1,
                "specialist": role,
                "action": action,
                "target": target,
                "risk": risk,
                "requires_authorization": True,
                "requires_scope_check": True,
                "requires_exact_action_approval": action in ACTIVE_ACTIONS,
                "replan_after": True,
            })
            if len(steps) >= max(1, min(int(max_steps), 20)):
                break
        if len(steps) >= max(1, min(int(max_steps), 20)):
            break
    data = {
        "schema_version": VERSION,
        "target": target,
        "objective": objective,
        "steps": steps,
        "execution": "plan -> operator approval -> preflight -> ToolManager -> evidence -> replan",
        "stop_conditions": ["authorization revoked", "target leaves scope", "kill switch", "approval mismatch", "tool failure", "evidence integrity failure"],
    }
    return _write(root, "governed-execution-plan-v313.json", data)


def request_approvals(root: str | Path, target: str, objective: str = "general", max_steps: int = 8) -> dict[str, Any]:
    root = Path(root)
    plan = build_governed_execution_plan(root, target, objective, max_steps)
    q = ApprovalQueue(root / "evidence")
    requests = []
    for step in plan["steps"]:
        if not step["requires_exact_action_approval"]:
            continue
        existing = q.find_active(step["action"], target)
        req = existing or q.submit(step["action"], target, f"V3.13 mission step {step['step']}: {objective}", risk=step["risk"])
        requests.append(req.to_dict())
    return _write(root, "governed-approval-requests-v313.json", {
        "schema_version": VERSION,
        "target": target,
        "objective": objective,
        "requests": requests,
        "message": "Approve each request separately before execution; approval is bound to exact action and target.",
    })


def execute_approved(root: str | Path, target: str, scope_file: str | Path, *, objective: str = "general", max_steps: int = 5,
                     authorization: bool = False, approval_tokens: dict[str, str] | None = None) -> dict[str, Any]:
    root = Path(root)
    if not authorization:
        return _write(root, "governed-execution-v313.json", {"schema_version": VERSION, "status": "blocked", "reason": "explicit authorization required"})

    from modules.scope import load_scope, is_valid_target_format
    from modules.tool_executor import build_executor
    from modules.approval_queue import ApprovalQueue

    if not is_valid_target_format(target):
        return _write(root, "governed-execution-v313.json", {"schema_version": VERSION, "status": "blocked", "reason": "invalid target"})
    allowed = load_scope(str(scope_file)) if Path(scope_file).exists() else []
    from modules.security import in_scope
    if not allowed or not in_scope(target, allowed):
        return _write(root, "governed-execution-v313.json", {"schema_version": VERSION, "status": "blocked", "reason": "target is out of authoritative scope"})

    tokens = approval_tokens or {}
    plan = build_governed_execution_plan(root, target, objective, max_steps)
    q = ApprovalQueue(root / "evidence")
    executor = build_executor(root, scope_file=scope_file)
    results = []
    for step in plan["steps"]:
        action = step["action"]
        # R0 local work is allowed after authorization/scope preflight; active
        # actions always need an exact request-bound token.
        if action in ACTIVE_ACTIONS:
            req = q.find_active(action, target)
            token = tokens.get(req.request_id) if req else None
            if not req or not token or not q.consume_token(req.request_id, token, action, target):
                results.append({"step": step["step"], "action": action, "status": "approval_required", "request_id": req.request_id if req else None})
                continue
        started = time.time()
        try:
            out = executor(action, target, root)
            result = {"step": step["step"], "action": action, "status": out.get("status", "completed") if isinstance(out, dict) else "completed", "result": out, "elapsed": round(time.time() - started, 3)}
        except Exception as exc:
            result = {"step": step["step"], "action": action, "status": "error", "error": str(exc), "elapsed": round(time.time() - started, 3)}
        results.append(result)
    return _write(root, "governed-execution-v313.json", {
        "schema_version": VERSION, "status": "completed", "target": target, "objective": objective,
        "authorization": True, "results": results,
        "next": "rebuild the plan from newly produced evidence before another execution cycle",
    })
