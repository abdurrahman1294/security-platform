"""V3.30 unified assessment execution and verification fabric.

Creates one canonical assessment state and one governed lifecycle over the
V3.24-V3.29 layers.  It is an integration/control-plane layer: execution is
never synthesized here; only already-registered bounded capabilities may be
selected for delegation.
"""
from __future__ import annotations
from pathlib import Path
from typing import Any, Iterable
import hashlib, json, time

VERSION = "3.30.0"
PERSPECTIVES = {
    "local_host", "physical_adjacent", "lan", "enterprise", "internet_ipv4",
    "internet_ipv6", "cellular_ipv4", "cellular_ipv6", "vpn", "cloud_vantage",
    "authenticated_user", "admin_authenticated", "testbed", "physical_lab",
}
SAFE_ACTIONS = {"observe", "enumerate", "fingerprint", "correlate", "validate", "retest", "remediate", "report"}
DENIED = {
    "credential_theft", "phishing", "credential_spraying_at_scale", "unrestricted_rce",
    "persistence", "covert_c2", "real_data_exfiltration", "uncontrolled_propagation",
    "destructive_impact", "carrier_bypass",
}
_SECRET_KEYS = {"password", "secret", "token", "private_key", "credential", "cookie", "session_cookie", "api_key"}


def _id(*parts: Any) -> str:
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:16]


def _secret_key(key: Any) -> bool:
    name = str(key).lower().replace("-", "_")
    return name in _SECRET_KEYS or any(term in name for term in ("password", "passwd", "secret", "token", "private_key", "credential", "session_cookie", "api_key"))


def _safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _safe(v) for k, v in value.items() if not _secret_key(k)}
    if isinstance(value, list): return [_safe(v) for v in value]
    if isinstance(value, tuple): return [_safe(v) for v in value]
    return value


def _write(root: str | Path, name: str, obj: Any) -> Path:
    p = Path(root) / "evidence" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(_safe(obj), indent=2, sort_keys=True), encoding="utf-8")
    return p


def normalize_evidence(items: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    out, seen = [], set()
    for i, raw in enumerate(items or []):
        if not isinstance(raw, dict): continue
        x = _safe(raw)
        eid = str(x.get("id") or _id("evidence", i, x.get("source", "unknown"), x.get("claim", "")))
        if eid in seen: continue
        seen.add(eid)
        out.append({
            "id": eid, "claim": str(x.get("claim", x.get("finding", x.get("status", "")))),
            "asset": str(x.get("asset", x.get("target", "unknown"))),
            "source": str(x.get("source", "unknown")),
            "trust": str(x.get("trust", x.get("provenance", "unknown"))),
            "status": str(x.get("status", "observed")),
            "observed_at": x.get("observed_at", x.get("timestamp", time.time())),
            "perspective": str(x.get("perspective", "unknown")),
        })
    return out


def normalize_failures(items: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    out = []
    for i, raw in enumerate(items or []):
        if not isinstance(raw, dict): continue
        x = _safe(raw)
        reason = str(x.get("reason", x.get("error", "unknown")))
        category = str(x.get("category", "unknown"))
        retryable = bool(x.get("retryable", category in {"transient", "tool_unavailable", "network"}))
        out.append({"id": str(x.get("id") or _id("failure", i, reason)), "action": str(x.get("action", "unknown")),
                    "reason": reason, "category": category, "retryable": retryable,
                    "scope_related": bool(x.get("scope_related", False)),
                    "authorization_related": bool(x.get("authorization_related", False)),
                    "recommended": "retry-with-backoff" if retryable else "preserve-and-replan"})
    return out


def build_canonical_state(*, target: str, objective: str, assets=None, evidence=None, hypotheses=None,
                          perspectives=None, timeline=None, capabilities=None, completed=None,
                          failures=None, remediation=None) -> dict[str, Any]:
    ps = list(dict.fromkeys(str(x) for x in (perspectives or [])))
    valid_ps = [x for x in ps if x in PERSPECTIVES]
    events = []
    for i, raw in enumerate(timeline or []):
        if not isinstance(raw, dict): continue
        x = _safe(raw)
        ts = x.get("timestamp", x.get("observed_at", i))
        try: order = float(ts)
        except (TypeError, ValueError): order = float(i)
        events.append({"id": str(x.get("id", f"event-{i+1}")), "timestamp": ts, "order": order,
                       "asset": str(x.get("asset", x.get("target", "unknown"))),
                       "state": str(x.get("state", x.get("claim", "unknown"))),
                       "perspective": str(x.get("perspective", "unknown"))})
    events.sort(key=lambda e: (e["order"], e["id"]))
    return {
        "target": target, "objective": objective, "assets": _safe(assets or []),
        "evidence": normalize_evidence(evidence), "hypotheses": _safe(hypotheses or []),
        "perspectives": valid_ps, "invalid_perspectives": [x for x in ps if x not in PERSPECTIVES],
        "timeline": events, "capabilities": _safe(capabilities or []),
        "completed": [str(x) for x in (completed or [])], "failures": normalize_failures(failures),
        "remediation": _safe(remediation or []),
    }


def assess_evidence_quality(evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    trust = {"authoritative": 1.0, "operator": .9, "provider": .8, "instrument": .75, "derived": .6, "external": .45, "unknown": .25}
    by_claim: dict[str, set[str]] = {}
    for e in evidence: by_claim.setdefault(e["claim"], set()).add(e["source"])
    out = []
    for e in evidence:
        freshness = 0.0 if e.get("status") in {"stale", "invalid"} else 1.0
        corroboration = min(1.0, len(by_claim.get(e["claim"], set())) / 3)
        score = .55 * trust.get(e["trust"], .25) + .25 * freshness + .20 * corroboration
        out.append({"evidence_id": e["id"], "quality": round(score, 4), "independent_sources": len(by_claim.get(e["claim"], set())),
                    "status": e["status"]})
    return out


def build_execution_plan(state: dict[str, Any], *, authorized: bool, execute: bool, scope_locked: bool,
                         authorization_current: bool, max_steps: int = 12) -> list[dict[str, Any]]:
    plan = []
    hypotheses = state.get("hypotheses", [])
    completed = set(state.get("completed", []))
    failures = {x.get("action") for x in state.get("failures", [])}
    for h in hypotheses[:max(1, min(50, int(max_steps)))]:
        hid = str(h.get("id", h.get("chain_id", _id("hypothesis", h))))
        sid = _id("execution-step", hid, state["target"])
        if sid in completed: status = "completed"
        elif not authorized or not scope_locked or not authorization_current: status = "blocked-by-governance"
        elif "validate" in failures: status = "replan-required"
        else: status = "delegable-to-existing-bounded-runtime"
        plan.append({"id": sid, "hypothesis_id": hid, "action": "validate", "safety_class": "R2_non_destructive_verify",
                     "target": state["target"], "requires": ["authoritative_scope", "fresh_evidence"],
                     "status": status, "execute_requested": bool(execute), "capability_synthesis": False})
    return plan


def build_failure_replan(failures: list[dict[str, Any]], *, completed: set[str]) -> list[dict[str, Any]]:
    alternatives = []
    for f in failures:
        if f["id"] in completed: continue
        alternatives.append({"failure_id": f["id"], "action": f["action"],
                             "strategy": "retry" if f["retryable"] else "perspective-shift-or-specialist-review",
                             "never": "expand scope or infer authorization"})
    return alternatives


def build_retest_plan(remediation: Iterable[dict[str, Any]] | None, evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{"id": _id("retest", i, str(x)), "finding_id": str(x.get("finding_id", x.get("id", i))),
             "action": "retest", "requires": ["fresh_evidence", "same-scope-baseline"],
             "success": "former claim no longer reproducible", "regression_check": True}
            for i, x in enumerate(remediation or []) if isinstance(x, dict)]


def validate_invariants(state: dict[str, Any], *, target: str, authorized: bool, execute: bool,
                        scope_locked: bool, authorization_current: bool) -> dict[str, Any]:
    blockers = []
    if not target: blockers.append("missing-target")
    if target != state.get("target"): blockers.append("target-state-mismatch")
    if state.get("invalid_perspectives"): blockers.append("invalid-perspective")
    if not scope_locked: blockers.append("scope-not-locked")
    if execute and not authorized: blockers.append("execution-without-authorization")
    if execute and not authorization_current: blockers.append("authorization-not-current")
    return {"ready": not blockers, "blockers": blockers,
            "invariants": {"scope_locked": bool(scope_locked), "authorization_current": bool(authorization_current),
                           "no_scope_expansion": True, "no_denied_autonomy": True,
                           "planning_execution_separated": True, "secret_capture_disabled": True,
                           "evidence_required_for_claims": True}}


def build_v330_fabric(root: str | Path, *, target: str, objective: str = "full-assessment", assets=None,
                      evidence=None, hypotheses=None, perspectives=None, timeline=None, capabilities=None,
                      completed=None, failures=None, remediation=None, authorized=False, execute=False,
                      scope_locked=True, authorization_current=None, max_steps=12) -> dict[str, Any]:
    current = bool(authorized) if authorization_current is None else bool(authorization_current)
    ps = list(perspectives or ["internet_ipv4"])
    state = build_canonical_state(target=target, objective=objective, assets=assets, evidence=evidence,
                                  hypotheses=hypotheses, perspectives=ps, timeline=timeline,
                                  capabilities=capabilities, completed=completed, failures=failures,
                                  remediation=remediation)
    readiness = validate_invariants(state, target=target, authorized=authorized, execute=execute,
                                    scope_locked=scope_locked, authorization_current=current)
    quality = assess_evidence_quality(state["evidence"])
    plan = build_execution_plan(state, authorized=authorized, execute=execute, scope_locked=scope_locked,
                                authorization_current=current, max_steps=max_steps)
    replans = build_failure_replan(state["failures"], completed=set(state["completed"]))
    retests = build_retest_plan(remediation, state["evidence"])
    result = {
        "schema_version": VERSION, "status": "ready" if readiness["ready"] else "blocked", "target": target,
        "objective": objective, "canonical_state": state, "evidence_quality": quality,
        "execution_plan": plan, "failure_replan": replans, "retest_plan": retests,
        "lifecycle": ["discover", "correlate", "hypothesize", "rank", "approve", "validate", "evidence",
                       "replan", "remediate", "retest", "report"],
        "governance": {"authorized": bool(authorized), "authorization_current": current,
                       "scope_locked": bool(scope_locked), "execute_requested": bool(execute),
                       "allowed_actions": sorted(SAFE_ACTIONS), "denied_classes": sorted(DENIED),
                       "execution_mode": "delegation-only", "unrestricted_exploit_generation": False},
        "readiness": readiness, "created_at": time.time(),
    }
    _write(root, "unified-assessment-v330.json", result)
    return result


def v330_test_matrix() -> dict[str, Any]:
    names = [
        "canonical-state-consistency", "target-lock", "scope-revocation", "authorization-revocation",
        "stale-evidence", "contradictory-evidence", "duplicate-evidence", "unknown-provenance",
        "malformed-evidence", "mixed-timestamp-ordering", "perspective-divergence", "cellular-ipv4-ipv6",
        "completed-step-resume", "interrupted-step", "transient-failure-replan", "permanent-failure-replan",
        "capability-unavailable", "denied-class-exclusion", "secret-redaction", "planning-execution-separation",
        "remediation-retest", "regression-detection", "scope-never-expands", "authorization-never-inferred",
        "hypothesis-never-becomes-compromise", "duplicate-hypothesis-stability", "empty-state", "invalid-input",
        "bounded-step-count", "artifact-determinism", "tool-output-poisoning", "state-drift-before-validation",
        "evidence-lineage-preserved", "failure-is-first-class", "teardown-status-preserved", "report-from-evidence-only",
    ]
    return {"schema_version": VERSION, "scenario_count": len(names),
            "scenarios": [{"id": _id(x), "name": x, "expected": "safe-degrade-or-deny"} for x in names],
            "invariants": ["canonical_state_is_authoritative", "never_expand_scope", "never_infer_authorization",
                           "never_claim_compromise_from_hypothesis", "never_select_denied_class",
                           "preserve_uncertainty", "execution_requires_governance", "retest_requires_fresh_evidence"]}
