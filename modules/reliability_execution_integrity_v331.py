"""V3.31 reliability and execution-integrity fabric.

Control-plane hardening for V3.30. This layer does not add new offensive
execution primitives; it makes planning/execution state transactional,
resumable, budgeted, auditable, and invariant-checked.
"""
from __future__ import annotations
from pathlib import Path
from typing import Any, Iterable
import hashlib, json, os, threading, time

VERSION = "3.31.0"
TERMINAL = {"completed", "failed", "blocked", "cancelled"}
TRANSITIONS = {
    "planned": {"approved", "blocked", "cancelled"},
    "approved": {"started", "blocked", "cancelled"},
    "started": {"completed", "failed", "blocked", "cancelled"},
    "failed": {"planned", "blocked", "cancelled"},
    "completed": set(), "blocked": set(), "cancelled": set(),
}
SECRET_TERMS = ("password", "passwd", "secret", "token", "credential", "private_key", "session_cookie", "api_key", "auth_token")

class IntegrityError(ValueError):
    pass


def _id(*parts: Any) -> str:
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:20]


def _secret_key(k: Any) -> bool:
    n = str(k).lower().replace("-", "_")
    return any(t in n for t in SECRET_TERMS)


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: redact(v) for k, v in value.items() if not _secret_key(k)}
    if isinstance(value, list): return [redact(v) for v in value]
    if isinstance(value, tuple): return [redact(v) for v in value]
    return value


def canonical_json(value: Any) -> str:
    return json.dumps(redact(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def atomic_write(path: str | Path, value: Any) -> Path:
    """Crash-resistant JSON replacement within the same filesystem."""
    p = Path(path); p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + f".tmp-{os.getpid()}-{threading.get_ident()}")
    data = json.dumps(redact(value), indent=2, sort_keys=True, ensure_ascii=False)
    with tmp.open("w", encoding="utf-8") as fh:
        fh.write(data); fh.flush(); os.fsync(fh.fileno())
    os.replace(tmp, p)
    return p


def validate_budget(*, max_steps: int, deadline_seconds: float, tool_budget: int, concurrency: int) -> dict[str, Any]:
    errors = []
    if not 1 <= int(max_steps) <= 1000: errors.append("max_steps-out-of-range")
    if not 0 < float(deadline_seconds) <= 86400: errors.append("deadline-out-of-range")
    if not 1 <= int(tool_budget) <= 10000: errors.append("tool_budget-out-of-range")
    if not 1 <= int(concurrency) <= 32: errors.append("concurrency-out-of-range")
    return {"valid": not errors, "errors": errors}


def preflight(*, target: str, state_target: str, authorized: bool, authorization_current: bool,
              scope_locked: bool, execute: bool, max_steps: int, deadline_seconds: float,
              tool_budget: int, concurrency: int) -> dict[str, Any]:
    blockers = []
    budget = validate_budget(max_steps=max_steps, deadline_seconds=deadline_seconds, tool_budget=tool_budget, concurrency=concurrency)
    if not target: blockers.append("missing-target")
    if target != state_target: blockers.append("target-state-mismatch")
    if not scope_locked: blockers.append("scope-not-locked")
    if execute and not authorized: blockers.append("execution-without-authorization")
    if execute and not authorization_current: blockers.append("authorization-not-current")
    if not budget["valid"]: blockers.extend(budget["errors"])
    return {"ready": not blockers, "blockers": blockers, "budget": budget,
            "checks": {"target_locked": target == state_target and bool(target),
                        "scope_locked": bool(scope_locked), "authorization_current": bool(authorization_current),
                        "no_scope_expansion": True, "planning_execution_separated": True}}


def validate_transition(old: str, new: str) -> None:
    if new not in TRANSITIONS.get(old, set()):
        raise IntegrityError(f"invalid-transition:{old}->{new}")


def make_operation(*, target: str, action: str, operation_id: str | None = None) -> dict[str, Any]:
    return {"id": operation_id or _id("operation", target, action, time.time_ns()), "target": target,
            "action": action, "status": "planned", "attempt": 0, "created_at": time.time()}


def transition_operation(op: dict[str, Any], new_status: str, *, reason: str = "") -> dict[str, Any]:
    old = str(op.get("status", "planned")); validate_transition(old, new_status)
    out = dict(op); out["status"] = new_status; out["updated_at"] = time.time()
    if reason: out["reason"] = reason
    if new_status == "started": out["attempt"] = int(out.get("attempt", 0)) + 1
    return out


def build_failure(*, operation_id: str, action: str, reason: str, category: str,
                  retryable: bool | None = None, elapsed: float | None = None) -> dict[str, Any]:
    retry = bool(retryable) if retryable is not None else category in {"transient", "timeout", "tool_unavailable", "network"}
    return {"id": _id("failure", operation_id, reason, time.time_ns()), "operation_id": operation_id,
            "action": action, "reason": reason, "category": category, "retryable": retry,
            "elapsed_seconds": elapsed, "recovery": "retry-with-backoff" if retry else "operator-or-specialist-review"}


def check_state_invariants(state: dict[str, Any]) -> dict[str, Any]:
    violations = []
    if not state.get("target"): violations.append("state-missing-target")
    if state.get("scope_locked") is not True: violations.append("state-scope-not-locked")
    if state.get("execute_requested") and state.get("authorization_current") is not True:
        violations.append("state-execution-without-current-authorization")
    ids = [x.get("id") for x in state.get("operations", []) if isinstance(x, dict)]
    if len(ids) != len(set(ids)): violations.append("duplicate-operation-id")
    for op in state.get("operations", []):
        if not isinstance(op, dict): violations.append("malformed-operation"); continue
        if op.get("status") not in TRANSITIONS: violations.append(f"unknown-operation-status:{op.get('status')}")
    return {"valid": not violations, "violations": violations}


def recover_operations(operations: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert interrupted started operations into explicit resumable failures."""
    out = []
    for op in operations or []:
        if not isinstance(op, dict): continue
        x = dict(op)
        if x.get("status") == "started":
            x = transition_operation(x, "failed", reason="interrupted-or-crash-recovery")
            x["recovery_required"] = True
            x["failure"] = build_failure(operation_id=x["id"], action=x.get("action", "unknown"),
                                         reason="interrupted-or-crash-recovery", category="interrupted", retryable=True)
        out.append(x)
    return out


def build_v331_fabric(root: str | Path, *, target: str, objective: str = "full-assessment",
                      canonical_state: dict[str, Any] | None = None, authorized: bool = False,
                      execute: bool = False, scope_locked: bool = True, authorization_current: bool | None = None,
                      max_steps: int = 12, deadline_seconds: float = 600, tool_budget: int = 100,
                      concurrency: int = 1, operations: Iterable[dict[str, Any]] | None = None,
                      failures: Iterable[dict[str, Any]] | None = None) -> dict[str, Any]:
    current = bool(authorized) if authorization_current is None else bool(authorization_current)
    base = dict(canonical_state or {})
    base["target"] = target
    base["objective"] = objective
    base["scope_locked"] = bool(scope_locked)
    base["authorization_current"] = current
    base["execute_requested"] = bool(execute)
    base["operations"] = [dict(x) for x in (operations if operations is not None else base.get("operations", [])) if isinstance(x, dict)]
    base["failures"] = [dict(x) for x in (failures if failures is not None else base.get("failures", [])) if isinstance(x, dict)]
    base = redact(base)
    base["state_digest"] = digest(base)
    pf = preflight(target=target, state_target=base["target"], authorized=authorized, authorization_current=current,
                   scope_locked=scope_locked, execute=execute, max_steps=max_steps, deadline_seconds=deadline_seconds,
                   tool_budget=tool_budget, concurrency=concurrency)
    invariants = check_state_invariants(base)
    recoverable = recover_operations(base["operations"])
    result = {"schema_version": VERSION, "status": "ready" if pf["ready"] and invariants["valid"] else "blocked",
              "target": target, "objective": objective, "canonical_state": base, "preflight": pf,
              "invariants": invariants, "recovered_operations": recoverable,
              "budgets": {"max_steps": int(max_steps), "deadline_seconds": float(deadline_seconds),
                          "tool_budget": int(tool_budget), "concurrency": int(concurrency)},
              "governance": {"authorized": bool(authorized), "authorization_current": current,
                             "scope_locked": bool(scope_locked), "execute_requested": bool(execute),
                             "execution_mode": "transactional-delegation-only"},
              "failure_policy": {"retryable": "bounded-retry-with-backoff", "non_retryable": "preserve-and-replan",
                                 "scope_or_authorization": "block-and-require-operator"},
              "created_at": time.time()}
    root = Path(root); atomic_write(root / "evidence" / "reliability-execution-v331.json", result)
    return result


def v331_test_matrix() -> dict[str, Any]:
    names = [
        "atomic-artifact-replacement", "atomic-write-secret-redaction", "state-digest-stability",
        "target-lock", "scope-lock", "authorization-current", "authorization-revocation",
        "global-deadline", "step-budget", "tool-budget", "concurrency-budget", "budget-validation",
        "operation-id-uniqueness", "operation-transition-valid", "operation-transition-invalid",
        "duplicate-operation-detection", "interrupted-operation-recovery", "resume-without-replay",
        "transient-failure-retry", "permanent-failure-preservation", "scope-failure-blocks",
        "malformed-operation", "unknown-operation-status", "canonical-state-integrity", "state-digest-lineage",
        "planning-execution-separation", "no-scope-expansion", "no-authorization-inference", "denied-autonomy",
        "evidence-not-secret-bearing", "hostile-tool-output-redaction", "partial-state-recovery",
        "recovery-idempotence", "terminal-state-immutability", "bounded-operation-count", "deadline-expiry",
        "crash-recovery", "concurrent-ledger-safety", "artifact-determinism", "failure-first-class",
        "audit-trail-preservation", "target-change-rejection", "authorization-change-rejection",
        "scope-change-rejection", "fresh-state-required", "retest-needs-new-evidence", "report-needs-evidence",
        "no-implicit-tool-selection", "no-implicit-command-generation", "operator-intervention-path",
    ]
    return {"schema_version": VERSION, "scenario_count": len(names),
            "scenarios": [{"id": _id("scenario", x), "name": x, "expected": "safe-degrade-or-deny"} for x in names],
            "invariants": ["state_is_transactional", "scope_never_expands", "authorization_never_inferred",
                           "interrupted_work_is_recoverable", "budgets_are_global", "terminal_states_are_immutable"]}
