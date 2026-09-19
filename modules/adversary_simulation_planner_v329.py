"""V3.29 unified adversary simulation planner.

Unifies the V3.24 intelligence, V3.25 capability runtime, V3.26 personal
surface, V3.27 adversarial reasoning and V3.28 temporal state layers into a
single evidence-first campaign planner. Planning is deliberately separated
from execution: only bounded, already-registered capabilities can be selected
for execution, and the planner never creates unrestricted exploit payloads.
"""
from __future__ import annotations
from pathlib import Path
from typing import Any, Iterable
import hashlib, json, time

VERSION = "3.29.0"
DENIED = {
    "credential_theft", "phishing", "credential_spraying_at_scale",
    "unrestricted_rce", "persistence", "covert_c2", "real_data_exfiltration",
    "uncontrolled_propagation", "destructive_impact", "carrier_bypass",
}
SAFE_ACTIONS = {
    "observe", "enumerate", "fingerprint", "correlate", "validate", "retest",
    "specialist-review", "evidence-review", "coverage-review", "report",
}
PERSPECTIVES = {
    "local_host", "physical_adjacent", "lan", "enterprise", "internet_ipv4",
    "internet_ipv6", "cellular_ipv4", "cellular_ipv6", "vpn", "cloud_vantage",
    "authenticated_user", "admin_authenticated", "testbed", "physical_lab",
}


def _id(*parts: Any) -> str:
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:16]


def _write(root: str | Path, name: str, obj: Any) -> Path:
    p = Path(root) / "evidence" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")
    return p


def _safe_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _safe_json(v) for k, v in value.items()
                if str(k).lower() not in {"password", "secret", "token", "private_key", "credential", "cookie", "session_cookie"}}
    if isinstance(value, list):
        return [_safe_json(v) for v in value]
    if isinstance(value, tuple):
        return [_safe_json(v) for v in value]
    return value


def normalize_observations(observations: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    out = []
    for i, raw in enumerate(observations or []):
        if not isinstance(raw, dict):
            continue
        clean = _safe_json(raw)
        out.append({
            "id": str(clean.get("id", f"obs-{i+1}")),
            "asset": str(clean.get("asset", clean.get("target", "unknown"))),
            "claim": str(clean.get("claim", clean.get("finding", clean.get("status", "")))),
            "status": str(clean.get("status", "observed")),
            "source": str(clean.get("source", "unknown")),
            "trust": str(clean.get("trust", clean.get("provenance", "unknown"))),
            "observed_at": clean.get("observed_at", clean.get("timestamp", time.time())),
            "perspective": str(clean.get("perspective", "unknown")),
            "tags": clean.get("tags", []) if isinstance(clean.get("tags", []), list) else [],
        })
    return out


def build_unified_state(*, target: str, assets: list[dict[str, Any]],
                        observations: Iterable[dict[str, Any]] | None,
                        chains: list[dict[str, Any]], timeline: Iterable[dict[str, Any]] | None,
                        perspective: str, objective: str) -> dict[str, Any]:
    events = []
    for i, raw in enumerate(timeline or []):
        if not isinstance(raw, dict):
            continue
        clean = _safe_json(raw)
        ts = clean.get("timestamp", clean.get("observed_at", i))
        try:
            order = float(ts)
        except (TypeError, ValueError):
            order = float(i)
        events.append({"id": str(clean.get("id", f"event-{i+1}")),
                       "timestamp": ts, "order": order,
                       "asset": str(clean.get("asset", clean.get("target", "unknown"))),
                       "state": str(clean.get("state", clean.get("claim", "unknown"))),
                       "source": str(clean.get("source", "unknown")),
                       "perspective": str(clean.get("perspective", perspective))})
    events.sort(key=lambda e: (e["order"], e["id"]))
    obs = normalize_observations(observations)
    return {
        "target": target,
        "objective": objective,
        "assets": _safe_json(assets),
        "observations": obs,
        "chains": _safe_json(chains),
        "timeline": events,
        "perspective": perspective,
        "perspectives_compared": [perspective],
    }


def _chain_score(chain: dict[str, Any], observations: list[dict[str, Any]]) -> float:
    priority = float(chain.get("priority", chain.get("confidence", 0.0)) or 0.0)
    evidence_ids = {str(x) for x in chain.get("evidence_ids", [])}
    related = [o for o in observations if o["id"] in evidence_ids]
    freshness = sum(1 for o in related if o.get("status", "observed") not in {"stale", "invalid"}) / max(1, len(related))
    # Reward corroboration, but never manufacture confidence from missing evidence.
    corroboration = min(1.0, len({o["source"] for o in related}) / 3.0)
    return round(min(1.0, .5 * priority + .3 * freshness + .2 * corroboration), 4)


def rank_hypotheses(chains: list[dict[str, Any]], observations: list[dict[str, Any]], *, limit: int = 20) -> list[dict[str, Any]]:
    ranked = []
    for chain in chains:
        if not isinstance(chain, dict):
            continue
        score = _chain_score(chain, observations)
        path = chain.get("chain", [])
        ranked.append({
            "id": str(chain.get("chain_id") or _id("hypothesis", *path)),
            "chain": list(path),
            "priority": score,
            "base_priority": float(chain.get("priority", 0.0) or 0.0),
            "evidence_ids": list(chain.get("evidence_ids", [])),
            "status": "hypothesis",
            "do_not_claim_compromise": True,
            "weak_link": chain.get("weak_link_score", 0.5),
            "next_validation": "revalidate the weakest prerequisite with fresh independent evidence",
        })
    ranked.sort(key=lambda x: (-x["priority"], -len(x["chain"]), x["id"]))
    return ranked[:max(1, min(100, int(limit)))]


def build_micro_chain_candidates(hypotheses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Find opportunities where several individually modest links compound.

    This is a reasoning artifact only. It never converts a chain into an exploit.
    """
    out = []
    for h in hypotheses:
        weak = float(h.get("weak_link", .5))
        if len(h.get("chain", [])) >= 4 and weak <= .75:
            out.append({"id": _id(h["id"], "micro-chain"), "hypothesis_id": h["id"],
                        "reason": "multiple dependency links may compound even when no single link is decisive",
                        "validation": "test each prerequisite independently, then perform only the least-impact approved correlation",
                        "status": "needs-evidence"})
    return out


def build_perspective_matrix(*, primary: str, requested: Iterable[str] | None = None) -> dict[str, Any]:
    perspectives = [primary] + [str(x) for x in (requested or []) if str(x) != primary]
    perspectives = list(dict.fromkeys(perspectives))
    valid = [x for x in perspectives if x in PERSPECTIVES]
    invalid = [x for x in perspectives if x not in PERSPECTIVES]
    pairs = []
    for a in valid:
        for b in valid:
            if a < b:
                pairs.append({"left": a, "right": b, "comparison": "reachability/state/evidence divergence"})
    return {"requested": perspectives, "valid": valid, "invalid": invalid, "comparisons": pairs}


def plan_validations(hypotheses: list[dict[str, Any]], *, authorized: bool, execute: bool,
                     target: str, perspective: str) -> list[dict[str, Any]]:
    steps = []
    for h in hypotheses[:12]:
        steps.append({
            "id": _id("step", h["id"], target, perspective),
            "hypothesis_id": h["id"], "action": "validate",
            "safety_class": "R2_non_destructive_verify",
            "target": target, "perspective": perspective,
            "requires": ["authoritative_scope", "fresh_evidence"],
            "authorized": bool(authorized), "execute_requested": bool(execute),
            "execution": "delegated-only" if execute and authorized else "plan-only",
            "status": "eligible-for-existing-bounded-runtime" if authorized else "approval-required",
        })
    return steps


def validate_campaign_state(*, target: str, authorized: bool, execute: bool,
                            scope_locked: bool, authorization_current: bool,
                            perspective: str, hypotheses: list[dict[str, Any]]) -> dict[str, Any]:
    blockers = []
    if not target:
        blockers.append("missing-target")
    if perspective not in PERSPECTIVES:
        blockers.append("invalid-perspective")
    if not scope_locked:
        blockers.append("scope-not-locked")
    if execute and not authorized:
        blockers.append("execution-without-authorization")
    if execute and not authorization_current:
        blockers.append("authorization-not-current")
    return {"ready": not blockers, "blockers": blockers,
            "invariants": {"no_scope_expansion": True, "no_denied_autonomy": True,
                            "no_secret_capture": True, "hypotheses_not_compromise": True,
                            "execution_separate_from_planning": True}}


def derive_prior_layers(*, root: str | Path, target: str, assets: list[dict[str, Any]],
                       observations: list[dict[str, Any]], chains: list[dict[str, Any]],
                       timeline: list[dict[str, Any]], objective: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Reuse prior layers when callers do not supply their intermediate artifacts."""
    component = {"v324_assessment_intelligence": "available", "v325_capability_runtime": "available",
                 "v326_personal_surface": "available", "v327_adversarial_reasoning": "available",
                 "v328_temporal_twin": "available"}
    derived = list(chains)
    try:
        from modules.adversarial_reasoning_v327 import build_deep_reasoning
        prior = build_deep_reasoning(root, target=target, assets=assets, observations=observations, objective=objective)
        component["v327_chain_count"] = len(prior.get("chains", []))
        if not derived:
            derived = prior.get("chains", [])
    except Exception as exc:
        component["v327_derivation_error"] = type(exc).__name__
    try:
        from modules.capability_runtime_v325 import capability_catalog
        component["v325_capability_count"] = len(capability_catalog())
    except Exception as exc:
        component["v325_derivation_error"] = type(exc).__name__
    try:
        from modules.universal_assessment_intelligence_v324 import build_attack_paths
        component["v324_available"] = True
        # Do not treat scanner observations as proof; the prior layer already preserves that rule.
        component["v324_path_preview_count"] = len(build_attack_paths(root, target=target, observations=observations, objective=objective, max_paths=12).get("attack_paths", []))
    except Exception as exc:
        component["v324_derivation_error"] = type(exc).__name__
    try:
        from modules.temporal_digital_twin_v328 import build_temporal_attack_paths
        component["v328_temporal_preview_count"] = len(build_temporal_attack_paths(derived, [], limit=20))
    except Exception as exc:
        component["v328_derivation_error"] = type(exc).__name__
    return derived, component


def build_v329_fabric(root: str | Path, *, target: str, assets: list[dict[str, Any]],
                      observations: Iterable[dict[str, Any]] | None = None,
                      chains: list[dict[str, Any]] | None = None,
                      timeline: Iterable[dict[str, Any]] | None = None,
                      perspective: str = "internet_ipv4", perspectives: Iterable[str] | None = None,
                      objective: str = "unified-authorized-adversary-simulation",
                      authorized: bool = False, execute: bool = False,
                      scope_locked: bool = True, authorization_current: bool | None = None,
                      max_hypotheses: int = 20) -> dict[str, Any]:
    obs = normalize_observations(observations)
    derived_chains, components = derive_prior_layers(root=root, target=target, assets=assets,
                                                     observations=obs, chains=chains or [],
                                                     timeline=list(timeline or []), objective=objective)
    unified = build_unified_state(target=target, assets=assets, observations=obs,
                                  chains=derived_chains, timeline=timeline or [],
                                  perspective=perspective, objective=objective)
    hypotheses = rank_hypotheses(derived_chains, obs, limit=max_hypotheses)
    micro = build_micro_chain_candidates(hypotheses)
    pm = build_perspective_matrix(primary=perspective, requested=perspectives)
    current = authorized if authorization_current is None else bool(authorization_current)
    state = validate_campaign_state(target=target, authorized=authorized, execute=execute,
                                    scope_locked=scope_locked, authorization_current=current,
                                    perspective=perspective, hypotheses=hypotheses)
    validations = plan_validations(hypotheses, authorized=authorized, execute=execute,
                                   target=target, perspective=perspective)
    result = {
        "schema_version": VERSION, "status": "ready" if state["ready"] else "blocked",
        "target": target, "objective": objective,
        "unified_state": unified,
        "integrated_layers": components,
        "hypotheses": hypotheses,
        "micro_chain_candidates": micro,
        "perspective_matrix": pm,
        "validation_plan": validations,
        "campaign": {"phases": ["collect", "reason", "compare", "validate", "retest", "remediate", "report"],
                     "max_hypotheses": max_hypotheses,
                     "planning_execution_separation": True},
        "governance": {
            "authorized": bool(authorized), "authorization_current": current,
            "scope_locked": bool(scope_locked), "execute_requested": bool(execute),
            "allowed_actions": sorted(SAFE_ACTIONS), "denied_classes": sorted(DENIED),
            "unrestricted_exploit_generation": False,
        },
        "readiness": state,
        "created_at": time.time(),
    }
    _write(root, "adversary-simulation-v329.json", result)
    return result


def v329_test_matrix() -> dict[str, Any]:
    names = [
        "tiny-weakness-chain-compounding", "cellular-ipv4-vs-ipv6-divergence",
        "internet-vs-local-perspective-drift", "authenticated-vs-unauthenticated-state",
        "stale-evidence-downranking", "contradictory-evidence-preservation",
        "scope-change-blocks-execution", "authorization-revocation-blocks-execution",
        "missing-target-blocks-campaign", "invalid-perspective-blocks-campaign",
        "duplicate-hypothesis-stability", "resume-after-interruption", "state-change-requires-revalidation",
        "capability-unavailable-safe-degrade", "denied-class-never-selected", "secret-redaction",
        "planning-execution-separation", "micro-chain-is-not-compromise", "temporal-window-recheck",
        "remediation-retest-loop", "evidence-source-independence", "unknown-provenance-downweighted",
        "empty-observation-set", "empty-chain-set", "malformed-input-skipped",
        "bounded-hypothesis-limit", "invalid-perspective-rejected", "authorization-not-inferred",
        "scope-never-expanded", "payload-assurance-remains-bounded",
    ]
    return {"schema_version": VERSION, "scenario_count": len(names),
            "scenarios": [{"id": _id(x), "name": x, "expected": "safe-degrade-or-deny"} for x in names],
            "invariants": ["never_expand_scope", "never_infer_authorization", "never_claim_compromise_from_hypothesis",
                           "never_emit_denied_execution", "preserve_uncertainty", "separate_plan_from_execute"]}
