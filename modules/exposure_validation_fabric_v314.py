from __future__ import annotations
"""V3.14 exposure-validation and nonlinear mission intelligence fabric.

Synthesizes useful patterns observed in autonomous pentesting and security-
validation platforms: branch-aware exploration, persistent clue/evidence state,
exposure-vs-control validation, continuous revalidation, and remediation loops.
It deliberately models attack behaviors and validation metadata rather than
embedding unrestricted payload/C2 primitives.
"""
import hashlib
import json
import time
from pathlib import Path
from typing import Any

from modules.atomic_io import atomic_write_json

VERSION = "3.14.0"

DECISIONS = {
    "validated_exploitable": "execution or trusted validation evidence demonstrates exploitability",
    "behaviorally_reachable": "attack-path/TTP evidence shows a plausible reachable path without executing a live exploit",
    "control_blocked": "a tested control prevented or detected the behavior",
    "restricted_unverified": "asset or technique could not be safely exercised under current ROE",
    "unverified": "insufficient evidence; do not promote to a confirmed finding",
}

CAPABILITY_SOURCES = {
    "nonlinear_agent_loop": ["MazeRunner"],
    "persistent_clue_graph": ["MazeRunner", "ATOBench"],
    "exposure_validation_without_exploit": ["Picus"],
    "continuous_control_validation": ["Picus", "AttackIQ"],
    "attack_path_and_kill_chain_validation": ["NodeZero", "Pentera", "Picus"],
    "living_attack_surface": ["Bishop Fox Cosmos", "NodeZero"],
    "threat_intel_to_scenario_metadata": ["Picus", "AttackIQ"],
    "remediation_retest_loop": ["Picus", "Pentera", "Strix"],
    "operator_api_task_tracking": ["Cobalt Strike", "Metasploit"],
    "multi_agent_specialization": ["Strix", "CAI", "Picus"],
}


def _write(root: Path, name: str, data: dict[str, Any]) -> dict[str, Any]:
    root.joinpath("evidence").mkdir(parents=True, exist_ok=True)
    atomic_write_json(root / "evidence" / name, data)
    return data


def _stable_id(*parts: Any) -> str:
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:16]


def build_capability_delta(root: str | Path) -> dict[str, Any]:
    """Record the capability layer added after V3.13."""
    data = {
        "schema_version": VERSION,
        "component": "exposure-validation-fabric",
        "new_capabilities": {
            "nonlinear_branch_search": "maintains competing hypotheses instead of a single linear task chain",
            "clue_persistence": "links observations, failed attempts, prerequisites and evidence across steps",
            "failure_review": "classifies failures as missing-prerequisite, blocked-control, scope/authorization, transient, or unknown",
            "exposure_verdicts": list(DECISIONS),
            "control_effectiveness": "records block/detect/miss outcomes with ATT&CK/TTP context",
            "continuous_revalidation": "generates delta-triggered revalidation plans after asset/control changes",
            "remediation_retest": "turns validated exposure into a fix decision and bounded retest contract",
            "scenario_metadata_ingestion": "converts threat/CVE/actor references into ATT&CK-mapped validation hypotheses without generating payloads",
            "ephemeral_engagement_metadata": "models disposable assessment workspaces and cleanup obligations",
        },
        "sources": CAPABILITY_SOURCES,
        "governance": "all active actions remain behind authorization, scope, ROE and exact-action approval gates",
    }
    return _write(root, "capability-delta-v314.json", data)


def build_nonlinear_mission(root: str | Path, target: str, objective: str = "general", max_branches: int = 4) -> dict[str, Any]:
    """Build competing evidence-driven branches; this is planning only."""
    root = Path(root)
    max_branches = max(1, min(int(max_branches), 8))
    branch_templates = [
        ("attack_surface", ["discover", "verify_reachability", "correlate_exposure"]),
        ("identity_path", ["enumerate_identity", "map_relationships", "validate_path"]),
        ("application_path", ["map_application", "correlate_source_runtime", "validate_exposure"]),
        ("cloud_path", ["inventory_cloud", "map_identity_resource_edges", "validate_exposure"]),
        ("control_validation", ["select_ttp", "validate_prevention_detection", "retest"]),
        ("mobile_path", ["static_inventory", "runtime_observation", "correlate_finding"]),
    ]
    branches = []
    for idx, (name, steps) in enumerate(branch_templates[:max_branches], 1):
        branches.append({
            "branch_id": _stable_id(target, objective, name),
            "name": name,
            "priority": round(1.0 / idx, 3),
            "status": "candidate",
            "steps": steps,
            "prerequisites": ["authorization", "scope", "applicable specialist capability"],
            "stop_on": ["scope drift", "authorization revoked", "kill switch", "integrity failure"],
        })
    data = {"schema_version": VERSION, "target": target, "objective": objective, "branches": branches,
            "selection": "score branches using evidence, novelty, prerequisite satisfaction, confidence and cost; retain alternatives for branch switching"}
    return _write(root, "nonlinear-mission-v314.json", data)


def record_clues(root: str | Path, observations: list[dict[str, Any]]) -> dict[str, Any]:
    root = Path(root)
    clues = []
    for obs in observations:
        if not isinstance(obs, dict):
            continue
        text = json.dumps(obs, sort_keys=True, default=str)
        clues.append({
            "clue_id": _stable_id(text),
            "observation": obs,
            "source_trust": obs.get("source_trust", "untrusted_until_correlated"),
            "supports": obs.get("supports", []),
            "contradicts": obs.get("contradicts", []),
            "timestamp": time.time(),
        })
    return _write(root, "clue-graph-v314.json", {"schema_version": VERSION, "clues": clues,
                                                     "rule": "observations are evidence, not authority"})


def review_failure(error: str, *, action: str = "", scope_or_authorization: bool = False) -> dict[str, Any]:
    text = (error or "").lower()
    if scope_or_authorization or any(x in text for x in ("scope", "authorization", "approval")):
        category = "scope_or_authorization"
    elif any(x in text for x in ("timeout", "temporar", "connection reset", "rate limit")):
        category = "transient"
    elif any(x in text for x in ("blocked", "denied", "forbidden", "detected")):
        category = "blocked_control_or_permission"
    elif any(x in text for x in ("missing", "prerequisite", "dependency", "not found")):
        category = "missing_prerequisite"
    else:
        category = "unknown"
    return {"action": action, "category": category, "retry": category == "transient",
            "branch_switch_candidate": category in {"missing_prerequisite", "blocked_control_or_permission", "unknown"},
            "error": error}


def validate_exposure(observation: dict[str, Any], *, control_result: str | None = None,
                      live_execution: bool = False, restricted: bool = False) -> dict[str, Any]:
    """Convert raw evidence into a defensible exposure verdict."""
    if restricted:
        decision = "restricted_unverified"
    elif control_result in {"blocked", "detected", "prevented"}:
        decision = "control_blocked"
    elif live_execution and observation.get("proof"):
        decision = "validated_exploitable"
    elif observation.get("reachable") and observation.get("attack_path"):
        decision = "behaviorally_reachable"
    else:
        decision = "unverified"
    return {"decision": decision, "meaning": DECISIONS[decision], "evidence": observation,
            "control_result": control_result, "confidence": observation.get("confidence", 0.0),
            "do_not_overclaim": decision not in {"validated_exploitable", "behaviorally_reachable"}}


def build_control_validation(root: str | Path, techniques: list[str] | None = None) -> dict[str, Any]:
    root = Path(root)
    techniques = techniques or []
    scenarios = [{"scenario_id": _stable_id("ttp", t), "technique": t, "status": "ready_for_governed_validation",
                   "requires": ["explicit authorization", "scope match", "exact-action approval"],
                   "outcomes": ["blocked", "detected", "missed", "not_exercised"]} for t in techniques]
    return _write(root, "control-validation-v314.json", {"schema_version": VERSION, "scenarios": scenarios,
                                                            "metric": "per-technique prevention/detection outcome with evidence"})


def build_remediation_retest(root: str | Path, findings: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    root = Path(root)
    findings = findings or []
    items = []
    for f in findings:
        decision = f.get("decision")
        if decision not in {"validated_exploitable", "behaviorally_reachable", "control_blocked"}:
            continue
        fid = f.get("finding_id") or _stable_id(json.dumps(f, sort_keys=True, default=str))
        items.append({"finding_id": fid, "decision": decision, "fix_choices": ["patch", "mitigate", "monitor", "accept_with_evidence"],
                      "retest": {"requires_new_approval": True, "same_scope": True, "same_evidence_contract": True,
                                 "success": "original exposure/control gap no longer reproduces"}})
    return _write(root, "remediation-retest-v314.json", {"schema_version": VERSION, "items": items,
                                                           "principle": "a finding is not closed until the remediation is revalidated"})


def build_continuous_revalidation(root: str | Path, baseline: dict[str, Any] | None = None) -> dict[str, Any]:
    root = Path(root)
    baseline = baseline or {}
    triggers = ["asset inventory delta", "service/protocol delta", "identity relationship delta", "cloud policy delta",
                "source/runtime delta", "control configuration delta", "new relevant threat/CVE intelligence"]
    data = {"schema_version": VERSION, "baseline_fingerprint": _stable_id(json.dumps(baseline, sort_keys=True, default=str)),
            "triggers": triggers, "on_trigger": ["recompute exposure priority", "select affected validation branches",
                                                     "request fresh exact-action approvals", "execute governed retest", "compare evidence", "update remediation state"],
            "cadence": "event-driven plus operator-scheduled assurance"}
    return _write(root, "continuous-revalidation-v314.json", data)


def build_v314_fabric(root: str | Path, target: str, objective: str = "general", observations: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    observations = observations or []
    return {
        "capability_delta": build_capability_delta(root),
        "nonlinear_mission": build_nonlinear_mission(root, target, objective),
        "clues": record_clues(root, observations),
        "control_validation": build_control_validation(root),
        "remediation_retest": build_remediation_retest(root),
        "continuous_revalidation": build_continuous_revalidation(root),
    }
