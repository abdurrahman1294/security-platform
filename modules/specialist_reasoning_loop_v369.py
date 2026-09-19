"""V3.69 Specialist-to-Specialist Reasoning Loop.

Coordinates governed specialists as a debate-and-convergence loop. Specialists
produce observations, other specialists challenge or corroborate them, and the
router selects the next highest-information registered capability. This is an
orchestration layer: it does not grant authority, expand scope, or translate
natural language into shell commands.
"""
from __future__ import annotations
import hashlib, json, time
from pathlib import Path
from typing import Any
from modules.specialist_orchestrator_v368 import select_specialists
from modules.hypothesis_dependency_engine_v377 import build_state as build_hypothesis_state, load_prior as load_hypothesis_prior, write_state as write_hypothesis_state

VERSION = "3.77.0"

PHASES = {
    "web": ("probe", "web", "api"),
    "network": ("ports", "dns", "tls"),
    "cloud": ("cloud",),
    "identity": ("authenticated", "ad"),
    "osint": ("recon",),
    # Intelligence specialists are connected to their actual V3.67 engines below.
    "attack-path": ("__attack_path__",),
    "rare-case": ("__rare_case__",),
}

CROSS_CHECKS = {
    "web": ("identity", "network", "rare-case"),
    "network": ("web", "cloud", "rare-case"),
    "cloud": ("identity", "network", "rare-case"),
    "identity": ("web", "cloud", "rare-case"),
    "osint": ("web", "identity", "rare-case"),
    "attack-path": ("web", "network", "identity", "cloud"),
    "rare-case": ("web", "network", "identity", "cloud"),
}


def _fp(*parts: Any) -> str:
    return hashlib.sha256("|".join(str(x or "") for x in parts).lower().encode()).hexdigest()[:16]


def _summarize(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        # Keep the artifact bounded while preserving the shape needed for correlation.
        return {k: value[k] for k in list(value)[:30]}
    return {"result": str(value)[:5000]}


def _signal_text(rows: list[dict[str, Any]]) -> str:
    return json.dumps(rows[-30:], ensure_ascii=False).lower()


def _action_outcome(result: Any, evidence_produced: bool = False) -> tuple[str, bool, str]:
    """Normalize execution outcome separately from evidence truth.

    A zero exit code proves only that the registered action executed successfully;
    it does not prove that usable evidence was produced. Evidence production is
    supplied by the evidence-delta verifier in ``run_loop``.
    """
    if not isinstance(result, dict):
        return "completed", bool(evidence_produced), "result-returned"
    status = str(result.get("status", "")).strip().lower()
    rc = result.get("returncode", result.get("naabu_returncode", result.get("nuclei_returncode")))
    if isinstance(rc, bool):
        rc = int(rc)
    if isinstance(rc, int) and rc != 0:
        return "failed", False, f"returncode={rc}"
    if status in {"failed", "error", "blocked", "unavailable", "skipped"}:
        return status, False, status
    if status == "partial":
        return "partial", bool(evidence_produced), "partial"
    return "completed", bool(evidence_produced), ("evidence-verified" if evidence_produced else "execution-succeeded-no-evidence")


def _evidence_snapshot(root: Path) -> dict[str, str]:
    """Return path -> content hash for evidence artifacts."""
    ev = root / "evidence"
    snap: dict[str, str] = {}
    if not ev.exists():
        return snap
    for path in ev.rglob("*"):
        if not path.is_file():
            continue
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            snap[str(path.relative_to(ev))] = digest
        except OSError:
            continue
    return snap


def _evidence_delta(root: Path, before: dict[str, tuple[int, int]]) -> list[str]:
    """Return non-empty evidence artifacts created or changed by an action."""
    ev = root / "evidence"
    after = _evidence_snapshot(root)
    changed = []
    for name, meta in after.items():
        if name not in before or before[name] != meta:
            try:
                if (ev / name).stat().st_size > 0:
                    changed.append(name)
            except OSError:
                continue
    return sorted(changed)


def _challenges(rows: list[dict[str, Any]], selected: list[dict[str, Any]]) -> list[dict[str, Any]]:
    successful = {x["specialist"] for x in rows if x.get("evidence_produced")}
    names = {x["specialist"] for x in selected}
    out = []
    for source in sorted(names):
        for peer in CROSS_CHECKS.get(source, ()):
            if peer not in names:
                continue
            if source in successful and peer in successful:
                status = "evidence_available"
                basis = ["independent evidence exists for both domains"]
            elif source in successful and peer not in successful:
                status = "not_tested"
                basis = [f"{peer} produced no successful evidence"]
            else:
                status = "not_tested"
                basis = [f"{source} produced no successful evidence"]
            out.append({
                "from": source, "to": peer,
                "question": f"Can {peer} corroborate or contradict the {source} hypothesis?",
                "basis": basis,
                "status": status,
                "corroboration_claim": False,
            })
    return out

def run_loop(*, engine: Any, objective: str, story: str = "", max_rounds: int = 3,
             max_specialists: int = 5, approval_token: str = "", authorized: bool = False) -> dict[str, Any]:
    if not objective.strip():
        raise ValueError("objective is required")
    root = Path(engine.e.output)
    root.mkdir(parents=True, exist_ok=True)
    if not authorized:
        out = {"schema_version": VERSION, "status": "blocked", "reason": "authorization-required",
               "rounds": [], "convergence": {"status": "not-started"}}
        _write(root, out); return out

    selected = select_specialists(story=story, objective=objective, max_specialists=max_specialists)
    completed: set[str] = set()
    failed: set[str] = set()
    rounds: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    hypothesis_state = load_hypothesis_prior(root)

    for round_no in range(1, max(1, min(int(max_rounds), 5)) + 1):
        actions = []
        # Re-rank specialists every round. This keeps the loop adaptive without
        # permitting arbitrary execution paths.
        selected = select_specialists(story=story, objective=objective,
                                       findings=evidence, observations=evidence,
                                       max_specialists=max_specialists)
        for item in selected:
            name = item["specialist"]
            for phase in PHASES.get(name, ()):
                key = f"{name}:{phase}"
                if key in completed or key in failed:
                    continue
                if phase in {"cloud", "authenticated", "ad"} and not approval_token:
                    actions.append({"specialist": name, "phase": phase, "status": "blocked", "reason": "approval-required"})
                    failed.add(key); continue
                fn = getattr(engine, phase, None)
                if not callable(fn):
                    actions.append({"specialist": name, "phase": phase, "status": "unavailable"})
                    failed.add(key); continue
                try:
                    evidence_before = _evidence_snapshot(root)
                    if phase == "__attack_path__":
                        result = engine.autonomous_attack_path_v367(story=story)
                    elif phase == "__rare_case__":
                        result = engine.rare_case_reasoner_v367(problem=objective, story=story)
                    else:
                        result = fn("aws") if phase == "cloud" else fn()
                    evidence_artifacts = _evidence_delta(root, evidence_before)
                    outcome, evidence_produced, outcome_detail = _action_outcome(
                        result, evidence_produced=bool(evidence_artifacts)
                    )
                    row = {"specialist": name, "phase": phase, "status": outcome,
                           "execution_status": outcome,
                           "evidence_status": "verified" if evidence_produced else "none",
                           "evidence_produced": evidence_produced,
                           "evidence_artifacts": evidence_artifacts,
                           "outcome_detail": outcome_detail,
                           "summary": _summarize(result)}
                    actions.append(row)
                    if evidence_produced:
                        evidence.append(row)
                    completed.add(key) if outcome in {"completed", "partial"} else failed.add(key)
                except Exception as exc:
                    row = {"specialist": name, "phase": phase, "status": "error",
                           "execution_status": "error", "evidence_status": "none",
                           "evidence_produced": False, 
                           "outcome_detail": "exception",
                           "error": f"{type(exc).__name__}:{str(exc)[:500]}"}
                    actions.append(row); failed.add(key)

        challenges = _challenges(evidence, selected)
        successful_actions = sum(1 for x in actions if x.get("evidence_produced"))
        independent_pairs = sum(1 for x in challenges if x.get("status") == "evidence_available")
        successful_executions = sum(1 for x in actions if x.get("execution_status") in {"completed", "partial"})
        attempted_actions = sum(1 for x in actions if x.get("status") not in {"blocked", "unavailable", "skipped"})
        # Information gain is tied to actual evidence-producing work and independent
        # evidence availability, never to the number of generated questions.
        info_gain = round(min(1.0, 0.20 * successful_actions + 0.10 * independent_pairs), 3)
        rounds.append({"round": round_no, "actions": actions, "cross_checks": challenges,
                       "information_gain": info_gain,
                       "successful_executions": successful_executions,
                       "evidence_producing_actions": successful_actions})
        if not any(x.get("status") in {"completed", "partial"} for x in actions):
            break

    corroborated = sum(1 for r in rounds for c in r["cross_checks"] if c["status"] == "evidence_available")
    attempted = sum(1 for r in rounds for a in r["actions"] if a.get("evidence_produced"))
    successful_executions_total = sum(r.get("successful_executions", 0) for r in rounds)
    remaining = [a for r in rounds for a in r["actions"] if a.get("status") in {"blocked", "unavailable"}]
    all_actions = [a for r in rounds for a in r["actions"]]
    hypothesis_state = build_hypothesis_state(objective=objective, story=story, evidence=evidence, actions=all_actions, prior=hypothesis_state)
    write_hypothesis_state(root, hypothesis_state)
    blocked_hypotheses = hypothesis_state.get("blocked_dependencies", [])
    unresolved_hypotheses = hypothesis_state.get("high_value_next_tests", [])
    if blocked_hypotheses:
        status = "blocked_pending_evidence"
        stopping_reason = "high-value-hypothesis-blocked-by-governance-or-prerequisite"
    elif unresolved_hypotheses:
        status = "ready_for_operator"
        stopping_reason = "high-value-hypothesis-needs-targeted-test"
    elif attempted:
        status = "converged"
        stopping_reason = "no-new-evidence-producing-actions"
    else:
        status = "partial"
        stopping_reason = "no-evidence-produced"
    out = {
        "schema_version": VERSION, "status": status, "objective": objective[:10000], "story": story[:30000],
        "rounds": rounds, "specialists": selected,
        "hypotheses": hypothesis_state.get("hypotheses", []),
        "hypothesis_dependency_engine": {"version": "3.77.0", "status": hypothesis_state.get("status"), "finding_claims_allowed": False, "state_artifact": "evidence/hypothesis-dependency-v377.json"},
        "convergence": {"status": status, "completed_actions": attempted,
                        "successful_executions": sum(r.get("successful_executions", 0) for r in rounds),
                        "evidence_producing_actions": attempted,
                        "cross_checks_with_independent_evidence": corroborated,
                        "hypothesis_challenge": True, "reassessment_each_round": True,
                        "stopping_reason": stopping_reason,
                        "remaining_blocked_or_unavailable": len(remaining),
                        "successful_executions": successful_executions_total,
                        "hypothesis_status": hypothesis_state.get("status"),
                        "high_value_next_tests": hypothesis_state.get("high_value_next_tests", [])[:5],
                        "blocked_dependencies": hypothesis_state.get("blocked_dependencies", [])[:5]},
        "governance": {"authorization_checked": True, "scope_policy_owned_by_engine": True,
                       "registered_entrypoints_only": True, "no_arbitrary_shell": True,
                       "no_scope_expansion": True, "approval_token_required_for_sensitive_specialists": True},
        "run_fingerprint": _fp(getattr(engine.e, "target", ""), objective, story), "created_at": time.time(),
    }
    _write(root, out)
    return out


def _write(root: Path, out: dict[str, Any]) -> None:
    p = root / "evidence"; p.mkdir(parents=True, exist_ok=True)
    (p / "specialist-reasoning-loop-v369.json").write_text(json.dumps(out, indent=2, sort_keys=True), encoding="utf-8")
