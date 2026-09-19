"""V3.23 Universal Execution Graph.

A governed evidence-driven planner for moving between specialist domains.
It consumes normalized observations, builds an evidence/factor graph, scores
candidate next steps, creates alternate hypotheses after failure, and tracks
coverage across attack surfaces and perspectives.

This module is deliberately a planner/orchestrator. It does not add arbitrary
remote execution, credential theft, persistence, stealth, propagation,
destructive actions, or unrestricted RCE. Consequential actions remain behind
the platform's existing scope/ROE/approval contracts and specialist adapters.
"""
from __future__ import annotations
import hashlib, json, time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Iterable

from modules.atomic_io import atomic_write_json
from modules.universal_attack_surface_fabric_v320 import ATTACK_SURFACES, PERSPECTIVES
from modules.universal_specialist_router_v322 import SPECIALIST_ROUTES, R4_PROCEDURES

VERSION = "3.23.0"

# Safe planning actions. The graph may recommend a specialist procedure but
# never turns the recommendation into authority to execute it.
SAFE_ACTIONS = {
    "observe", "enumerate", "fingerprint", "correlate", "validate", "retest",
    "specialist-review", "evidence-review", "coverage-review", "report"
}
DENIED_CLASSES = {
    "unrestricted_rce", "destructive_impact", "covert_c2", "uncontrolled_propagation",
    "real_data_exfiltration", "credential_spraying_at_scale", "carrier_bypass"
}

@dataclass(frozen=True)
class Candidate:
    surface: str
    specialist: str
    perspective: str
    action: str
    score: float
    rationale: list[str]
    prerequisites: list[str]
    governance: str = "existing-scope-and-approval-contract"


def _hash(*parts: Any) -> str:
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:16]


def _write(root: Path, name: str, data: dict[str, Any]) -> None:
    root.joinpath("evidence").mkdir(parents=True, exist_ok=True)
    atomic_write_json(root / "evidence" / name, data)


def normalize_observations(observations: Iterable[Any] | None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in observations or []:
        if isinstance(item, str):
            out.append({"type": "note", "value": item})
        elif isinstance(item, dict):
            clean = {str(k): v for k, v in item.items() if k not in {"secret", "password", "token", "private_key"}}
            out.append(clean)
    return out


def ingest_evidence_directory(evidence_dir: str | Path, *, max_files: int = 200) -> list[dict[str, Any]]:
    """Load existing JSON evidence artifacts as observations, never execute them."""
    path = Path(evidence_dir)
    observations: list[dict[str, Any]] = []
    if not path.is_dir():
        return observations
    for file in sorted(path.glob("*.json"))[:max_files]:
        try:
            data = json.loads(file.read_text(encoding="utf-8"))
        except Exception:
            continue
        observations.append({"type": "evidence-artifact", "artifact": file.name, "data": data})
    return observations


def build_evidence_graph(root: str | Path, *, target: str, observations: Iterable[Any] | None = None) -> dict[str, Any]:
    root = Path(root)
    obs = normalize_observations(observations)
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    for i, item in enumerate(obs):
        node_id = "E-" + _hash(target, i, json.dumps(item, sort_keys=True, default=str))
        nodes[node_id] = {"id": node_id, "kind": "evidence", "observation": item, "confidence": float(item.get("confidence", 0.5)) if isinstance(item, dict) else 0.5}
        surface = item.get("surface") if isinstance(item, dict) else None
        if surface in ATTACK_SURFACES:
            s_id = "S-" + surface
            nodes.setdefault(s_id, {"id": s_id, "kind": "surface", "surface": surface})
            edges.append({"from": node_id, "to": s_id, "relation": "supports"})
    # Always retain a target anchor so an empty evidence set is a valid graph.
    t_id = "T-" + _hash(target)
    nodes[t_id] = {"id": t_id, "kind": "target", "target": target}
    data = {"schema_version": VERSION, "target": target, "nodes": list(nodes.values()), "edges": edges, "observation_count": len(obs)}
    _write(root, "universal-evidence-graph-v323.json", data)
    return data


def _surface_relevance(surface: str, obs: list[dict[str, Any]]) -> float:
    explicit = sum(1 for x in obs if x.get("surface") == surface)
    related = sum(1 for x in obs if surface in str(x.get("related_surfaces", [])))
    return min(1.0, 0.15 * explicit + 0.05 * related)


def build_coverage_state(*, surfaces: Iterable[str] | None = None, perspectives: Iterable[str] | None = None, observations: Iterable[Any] | None = None, completed: Iterable[dict[str, Any]] | None = None) -> dict[str, Any]:
    selected_surfaces = [s for s in dict.fromkeys(surfaces or ATTACK_SURFACES) if s in ATTACK_SURFACES]
    selected_perspectives = [p for p in dict.fromkeys(perspectives or PERSPECTIVES) if p in PERSPECTIVES]
    done = list(completed or [])
    done_keys = {(x.get("surface"), x.get("perspective")) for x in done}
    matrix = []
    for surface in selected_surfaces:
        for perspective in selected_perspectives:
            matrix.append({"surface": surface, "perspective": perspective, "status": "completed" if (surface, perspective) in done_keys else "pending"})
    total = len(matrix); complete = sum(x["status"] == "completed" for x in matrix)
    return {"surfaces": selected_surfaces, "perspectives": selected_perspectives, "matrix": matrix, "total": total, "completed": complete, "coverage_ratio": (complete / total if total else 1.0)}


def score_candidates(*, target: str, observations: Iterable[Any] | None = None, surfaces: Iterable[str] | None = None, perspectives: Iterable[str] | None = None, completed: Iterable[dict[str, Any]] | None = None, failed: Iterable[dict[str, Any]] | None = None, max_candidates: int = 12) -> list[dict[str, Any]]:
    obs = normalize_observations(observations)
    failed_list = list(failed or [])
    done = list(completed or [])
    done_keys = {(x.get("surface"), x.get("perspective")) for x in done}
    failures = {(x.get("surface"), x.get("perspective")) for x in failed_list}
    candidates: list[Candidate] = []
    for surface in [s for s in dict.fromkeys(surfaces or ATTACK_SURFACES) if s in ATTACK_SURFACES]:
        specialist = SPECIALIST_ROUTES.get(surface, "unmapped")
        if specialist == "unmapped":
            continue
        for perspective in [p for p in dict.fromkeys(perspectives or PERSPECTIVES) if p in PERSPECTIVES]:
            key = (surface, perspective)
            if key in done_keys:
                continue
            relevance = _surface_relevance(surface, obs)
            novelty = 0.30 if key not in failures else 0.05
            perspective_bonus = 0.10 if perspective in {"authenticated_user", "admin_authenticated", "cloud_vantage", "cellular_ipv4", "cellular_ipv6"} else 0.0
            specialist_bonus = 0.15 if surface not in {"human_social", "physical_facility"} else 0.02
            score = min(1.0, 0.25 + relevance + novelty + perspective_bonus + specialist_bonus)
            rationale = ["surface is in the universal inventory", "specialist route is registered"]
            if relevance: rationale.append("existing evidence increases relevance")
            if key in failures: rationale.append("previous branch failed; deprioritize until prerequisites change")
            candidates.append(Candidate(surface, specialist, perspective, "specialist-review", round(score, 4), rationale, ["target-in-scope", "specialist-contract"] if specialist != "unmapped" else ["scope-review"]))
    candidates.sort(key=lambda x: (-x.score, x.surface, x.perspective))
    return [asdict(x) for x in candidates[:max(1, max_candidates)]]


def generate_alternatives(*, failed_step: dict[str, Any], observations: Iterable[Any] | None = None, max_alternatives: int = 5) -> list[dict[str, Any]]:
    surface = failed_step.get("surface", "")
    perspective = failed_step.get("perspective", "")
    reason = str(failed_step.get("reason", "unknown"))
    alternatives = []
    for p in PERSPECTIVES:
        if p == perspective:
            continue
        alternatives.append({"type": "perspective-shift", "surface": surface, "perspective": p, "reason": f"retry from a distinct authorized vantage after failure: {reason}"})
        if len(alternatives) >= max_alternatives:
            break
    if surface in ATTACK_SURFACES:
        for sibling in ATTACK_SURFACES[surface].get("tests", [])[:2]:
            alternatives.append({"type": "test-substitution", "surface": surface, "test": sibling, "reason": "use a different non-destructive test supported by the same specialist"})
    return alternatives[:max_alternatives]


def build_execution_graph(root: str | Path, *, target: str, observations: Iterable[Any] | None = None, surfaces: Iterable[str] | None = None, perspectives: Iterable[str] | None = None, completed: Iterable[dict[str, Any]] | None = None, failed: Iterable[dict[str, Any]] | None = None, objective: str = "full-assessment", max_candidates: int = 12) -> dict[str, Any]:
    root = Path(root)
    obs = normalize_observations(observations)
    coverage = build_coverage_state(surfaces=surfaces, perspectives=perspectives, observations=obs, completed=completed)
    evidence = build_evidence_graph(root, target=target, observations=obs)
    candidates = score_candidates(target=target, observations=obs, surfaces=surfaces, perspectives=perspectives, completed=completed, failed=failed, max_candidates=max_candidates)
    failed_list = list(failed or [])
    alternatives = [generate_alternatives(f, observations=obs) for f in failed_list[-3:]]
    graph_edges = []
    for c in candidates:
        graph_edges.append({"from": "target", "to": f"{c['surface']}@{c['perspective']}", "relation": "next-candidate", "score": c["score"]})
    data = {
        "schema_version": VERSION, "target": target, "objective": objective,
        "status": "ready" if candidates else "coverage-exhausted",
        "coverage": coverage, "evidence_graph": {"node_count": len(evidence["nodes"]), "edge_count": len(evidence["edges"])},
        "candidate_steps": candidates, "alternative_hypotheses": alternatives,
        "graph_edges": graph_edges,
        "governance": {"authorization_required": True, "scope_recheck_before_execution": True, "approval_for_consequential_actions": True, "no_scope_expansion": True, "denied_autonomy_classes": sorted(DENIED_CLASSES), "r4_procedures": sorted(R4_PROCEDURES)},
        "generated_at": time.time(),
    }
    _write(root, "universal-execution-graph-v323.json", data)
    return data


def advance_execution_graph(root: str | Path, *, target: str, state: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    """Update graph state from an observed result without executing anything."""
    completed = list(state.get("completed", []))
    failed = list(state.get("failed", []))
    record = {"surface": result.get("surface"), "perspective": result.get("perspective"), "status": result.get("status"), "reason": result.get("reason", "")}
    if result.get("status") in {"completed", "validated", "verified", "delegated"}:
        completed.append(record)
    else:
        failed.append(record)
    return build_execution_graph(root, target=target, observations=state.get("observations", []) + ([result.get("evidence")] if isinstance(result.get("evidence"), dict) else []), surfaces=state.get("surfaces"), perspectives=state.get("perspectives"), completed=completed, failed=failed, objective=state.get("objective", "full-assessment"), max_candidates=state.get("max_candidates", 12))


def run_execution_graph(root: str | Path, *, target: str, scope_file: str | Path, observations: Iterable[Any] | None = None, surfaces: Iterable[str] | None = None, perspectives: Iterable[str] | None = None, authorized: bool = False, execute: bool = False, max_iterations: int = 3, max_candidates: int = 8, timeout: int = 600, objective: str = "full-assessment") -> dict[str, Any]:
    """Run a bounded graph loop using the existing governed V3.22/V3.21 router.

    Only registered safe adapters may execute. Specialist-only surfaces are
    recorded as delegated; the graph never synthesizes a new exploit adapter.
    """
    root = Path(root)
    if not authorized:
        return {"schema_version": VERSION, "status": "blocked", "reason": "explicit_authorization_required"}
    if not execute:
        plan = build_execution_graph(root, target=target, observations=observations, surfaces=surfaces, perspectives=perspectives, objective=objective, max_candidates=max_candidates)
        return {"schema_version": VERSION, "status": "plan-only", "plan": plan}
    if not scope_file or not Path(scope_file).is_file():
        return {"schema_version": VERSION, "status": "blocked", "reason": "authoritative_scope_required"}
    state: dict[str, Any] = {"observations": normalize_observations(observations), "surfaces": list(surfaces or ATTACK_SURFACES), "perspectives": list(perspectives or PERSPECTIVES), "completed": [], "failed": [], "objective": objective, "max_candidates": max_candidates}
    history: list[dict[str, Any]] = []
    from modules.universal_specialist_router_v322 import execute_universal_router
    for _ in range(max(1, min(max_iterations, 20))):
        plan = build_execution_graph(root, target=target, observations=state["observations"], surfaces=state["surfaces"], perspectives=state["perspectives"], completed=state["completed"], failed=state["failed"], objective=objective, max_candidates=max_candidates)
        candidates = plan.get("candidate_steps", [])
        if not candidates:
            break
        candidate = candidates[0]
        result = execute_universal_router(root, target=target, scope_file=scope_file, perspective=candidate["perspective"], authorized=authorized, execute=True, surfaces=[candidate["surface"]], max_steps=1, timeout=timeout, objective=objective)
        status = result.get("status", "unknown")
        record = {"surface": candidate["surface"], "perspective": candidate["perspective"], "specialist": candidate["specialist"], "status": status, "coverage": result.get("universal_safe_execution", {}).get("coverage", {}), "delegated": result.get("specialist_delegation", [])}
        history.append(record)
        if status in {"completed", "partial", "plan-only"} or record["delegated"]:
            state["completed"].append(record)
        else:
            state["failed"].append(record)
        state["observations"].append({"type": "graph-step", "surface": candidate["surface"], "perspective": candidate["perspective"], "status": status, "confidence": 0.5})
    final = build_execution_graph(root, target=target, observations=state["observations"], surfaces=state["surfaces"], perspectives=state["perspectives"], completed=state["completed"], failed=state["failed"], objective=objective, max_candidates=max_candidates)
    out = {"schema_version": VERSION, "status": "completed", "iterations": len(history), "history": history, "final_plan": final, "governance": final["governance"]}
    _write(root, "universal-execution-graph-run-v323.json", out)
    return out
