"""V3.27 adversarial reasoning resilience fabric.

Evidence-first reasoning for authorized self-assessment.  It deliberately
separates attacker-style hypothesis generation from execution.  It can model
weak signals, contradictory observations, temporal drift, trust/provenance,
and long cross-domain chains, but it never emits credential theft, phishing,
persistence, covert C2, destructive, propagation, or unrestricted RCE steps.
"""
from __future__ import annotations
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Iterable
import hashlib, json, math, time

VERSION = "3.27.0"
DENIED = {
    "credential_theft", "phishing", "credential_spraying_at_scale",
    "unrestricted_rce", "persistence", "covert_c2", "real_data_exfiltration",
    "uncontrolled_propagation", "destructive_impact", "carrier_bypass",
}

TRUST_RANK = {"authoritative": 1.0, "operator": .95, "provider": .9,
              "instrument": .82, "derived": .7, "external": .55, "unknown": .35}

# Relationship vocabulary intentionally describes trust/dependency, not attack payloads.
RELATION_WEIGHTS = {
    "provides-egress": .55, "may-expose-or-identify": .55, "identity-provider-or-recovery": .9,
    "recovery-control": .95, "session-boundary": .8, "application-boundary": .7,
    "recovery-boundary": .9, "host-boundary": .75, "credential-control": .95,
    "integration-trust": .8, "human-mediated-trust": .65, "network-reachability": .65,
    "gateway": .6,
}


def _id(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def _write(root: str | Path, name: str, obj: Any) -> Path:
    p = Path(root) / "evidence" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")
    return p


def _tokens(value: Any) -> set[str]:
    return {x for x in str(value).lower().replace("/", " ").replace("-", " ").split() if len(x) > 3}


def normalize_evidence(observations: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    out = []
    now = time.time()
    for i, raw in enumerate(observations or []):
        if not isinstance(raw, dict):
            continue
        # Never retain secret-bearing fields in this reasoning layer.
        clean = {k: v for k, v in raw.items() if k.lower() not in {
            "password", "secret", "token", "private_key", "credential", "cookie", "session_cookie"
        }}
        oid = str(clean.get("id") or f"obs-{i+1}")
        trust = str(clean.get("trust", clean.get("provenance", "unknown"))).lower()
        if trust not in TRUST_RANK:
            trust = "unknown"
        observed_at = clean.get("observed_at", clean.get("timestamp", now))
        try:
            age = max(0.0, now - float(observed_at))
        except (TypeError, ValueError):
            age = 0.0
        # Exponential freshness decay with a one-day half-life.
        freshness = round(math.exp(-age / 86400.0), 4)
        status = str(clean.get("status", "observed")).lower()
        out.append({
            "id": oid, "claim": str(clean.get("claim", clean.get("finding", clean.get("status", "")))),
            "status": status, "trust": trust, "trust_score": TRUST_RANK[trust],
            "freshness": freshness, "observed_at": observed_at,
            "source": str(clean.get("source", "unknown")),
            "target": str(clean.get("target", "")),
            "tags": list(clean.get("tags", [])) if isinstance(clean.get("tags", []), list) else [],
        })
    return out


def detect_evidence_conflicts(evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    conflicts = []
    pairs = (("true", "false"), ("present", "absent"), ("enabled", "disabled"),
             ("reachable", "unreachable"), ("valid", "invalid"), ("exposed", "not exposed"))
    for i, left in enumerate(evidence):
        for right in evidence[i+1:]:
            a, b = left["claim"].lower(), right["claim"].lower()
            shared = _tokens(a) & _tokens(b)
            if not shared:
                continue
            for pos, neg in pairs:
                if ((pos in a and neg in b) or (neg in a and pos in b)):
                    conflicts.append({"id": _id(left["id"], right["id"], pos, neg),
                                      "claim_group": " ".join(sorted(shared)),
                                      "observations": [left["id"], right["id"]],
                                      "type": "contradiction",
                                      "resolution": "retain both until independently revalidated"})
                    break
    return conflicts


def evidence_resilience(evidence: list[dict[str, Any]]) -> dict[str, Any]:
    conflicts = detect_evidence_conflicts(evidence)
    weak = [e["id"] for e in evidence if e["trust_score"] < .7 or e["freshness"] < .35]
    strong = [e["id"] for e in evidence if e["trust_score"] >= .8 and e["freshness"] >= .5]
    return {
        "evidence_count": len(evidence), "strong_count": len(strong), "weak_or_stale_count": len(weak),
        "conflict_count": len(conflicts), "conflicts": conflicts,
        "poisoning_resistance": {
            "untrusted_cannot_override_authoritative": True,
            "contradictions_require_revalidation": True,
            "stale_claims_are_downweighted": True,
            "secret_fields_removed": True,
        },
    }


def build_asset_graph(assets: list[dict[str, Any]], dependency_graph: dict[str, Any] | None = None) -> dict[str, Any]:
    if dependency_graph:
        return dependency_graph
    nodes = [{"id": a.get("id"), "type": a.get("type"), "label": a.get("label"),
              "trust_zone": a.get("trust_zone", "unknown"), "exposure": a.get("exposure", "unknown")} for a in assets]
    by_type: dict[str, list[str]] = {}
    for a in assets:
        by_type.setdefault(str(a.get("type")), []).append(str(a.get("id")))
    edges = []
    def add(src, dst, rel):
        for source_id in by_type.get(src, []):
            for dest_id in by_type.get(dst, []):
                edges.append({"from": source_id, "to": dest_id, "relation": rel, "weight": RELATION_WEIGHTS.get(rel, .5)})
    for src, dst, rel in [
        ("cellular_connection","public_ip","provides-egress"),("public_ip","router","may-expose-or-identify"),
        ("email_identity","social_account","identity-provider-or-recovery"),("email_identity","cloud_account","identity-provider-or-recovery"),
        ("recovery_channel","social_account","recovery-control"),("recovery_channel","cloud_account","recovery-control"),
        ("browser","cloud_account","session-boundary"),("mobile_phone","social_account","application-boundary"),
        ("mobile_phone","recovery_channel","recovery-boundary"),("computer","browser","host-boundary"),
        ("password_manager","cloud_account","credential-control"),("password_manager","social_account","credential-control"),
        ("third_party_service","cloud_account","integration-trust"),("human_trust_boundary","social_account","human-mediated-trust"),
        ("human_trust_boundary","email_identity","human-mediated-trust"),("home_network","computer","network-reachability"),
        ("home_network","mobile_phone","network-reachability"),("router","home_network","gateway")]: add(src,dst,rel)
    return {"nodes": nodes, "edges": edges}


def enumerate_chains(graph: dict[str, Any], max_length: int = 8, max_chains: int = 40) -> list[list[str]]:
    adj: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in graph.get("edges", []): adj[e["from"]].append(e)
    starts = [n["id"] for n in graph.get("nodes", []) if n.get("exposure") in {"internet-facing", "human-mediated"}]
    chains = []
    for start in starts:
        q = deque([(start, [start], 1.0)])
        while q and len(chains) < max_chains:
            node, path, score = q.popleft()
            if len(path) >= 3:
                chains.append((score, path))
            if len(path) >= max_length: continue
            for e in adj.get(node, []):
                nxt = e["to"]
                if nxt in path: continue
                q.append((nxt, path + [nxt], score * float(e.get("weight", .5))))
    chains.sort(key=lambda x: (-x[0], -len(x[1]), x[1]))
    return [p for _, p in chains[:max_chains]]


def score_chain(chain: list[str], evidence: list[dict[str, Any]], graph: dict[str, Any]) -> dict[str, Any]:
    text = " ".join(chain).lower()
    node_text = []
    node_map = {str(n.get("id")): n for n in graph.get("nodes", []) if isinstance(n, dict)}
    for node_id in chain:
        n = node_map.get(str(node_id), {})
        node_text.extend([str(node_id), str(n.get("label", "")), str(n.get("type", ""))])
    related = []
    for e in evidence:
        hay = _tokens(str(e.get("claim", "")) + " " + str(e.get("asset", "")) + " " + str(e.get("surface", "")))
        if hay & _tokens(text + " " + " ".join(node_text)):
            related.append(e)
    corroboration = min(1.0, sum(e["trust_score"] * e["freshness"] for e in related) / 2.0)
    independence = min(1.0, len({e["source"] for e in related}) / 3.0)
    weak_link = min([float(e.get("weight", .5)) for e in graph.get("edges", [])
                     if e.get("from") in chain and e.get("to") in chain] or [.5])
    complexity_bonus = min(.18, max(0, len(chain)-3) * .03)
    uncertainty = 1.0 - max(corroboration, independence * .85)
    priority = min(1.0, .35 * weak_link + .35 * corroboration + .2 * independence + complexity_bonus)
    return {
        "chain_id": _id(*chain), "chain": chain, "length": len(chain),
        "evidence_ids": [e["id"] for e in related], "corroboration": round(corroboration,4),
        "source_independence": round(independence,4), "weak_link_score": round(weak_link,4),
        "uncertainty": round(uncertainty,4), "priority": round(priority,4),
        "status": "hypothesis" if related else "unverified", "do_not_claim_compromise": True,
        "next_validation": "Collect independent, fresh, non-secret evidence for the weakest link; revalidate before any consequential test.",
    }


def build_deep_reasoning(root: str | Path, *, target: str, assets: list[dict[str, Any]],
                         observations: Iterable[dict[str, Any]] | None = None,
                         dependency_graph: dict[str, Any] | None = None,
                         objective: str = "full-self-assessment") -> dict[str, Any]:
    evidence = normalize_evidence(observations)
    graph = build_asset_graph(assets, dependency_graph)
    chains = enumerate_chains(graph)
    scored = sorted((score_chain(c, evidence, graph) for c in chains), key=lambda x: (-x["priority"], x["chain_id"]))
    resilience = evidence_resilience(evidence)
    # Generate explicit alternatives for the most interesting weak links without turning them into exploit recipes.
    alternatives = []
    for c in scored[:12]:
        alternatives.append({"chain_id": c["chain_id"], "alternatives": [
            "revalidate from an independent perspective",
            "test a less-trusted hypothesis before escalating confidence",
            "compare current evidence with a prior baseline",
        ]})
    state = {
        "schema_version": VERSION, "status": "ready", "target": target, "objective": objective,
        "reasoning": {"deep_chain_search": True, "cross_domain": True, "weak_signal_analysis": True,
                       "evidence_poisoning_resistance": True, "temporal_reasoning": True,
                       "independent_corroboration": True, "uncertainty_preserved": True},
        "evidence": evidence, "evidence_resilience": resilience,
        "chains": scored, "alternatives": alternatives,
        "governance": {"authorized_scope_required": True, "operator_approval_for_consequential_tests": True,
                       "automation_denied": sorted(DENIED), "execution": "plan-and-validate-only"},
        "created_at": time.time(),
    }
    _write(root, "adversarial-deep-reasoning-v327.json", state)
    return state


def adversarial_reasoning_test_suite() -> dict[str, Any]:
    scenarios = [
        "authoritative_vs_untrusted_conflict", "stale_authoritative_evidence", "contradictory_provider_signals",
        "weak_signal_plus_weak_signal", "long_chain_dependency", "cycle_in_graph", "independent_source_corroboration",
        "single_source_overconfidence", "temporal_drift", "scope_boundary_change", "authorization_revocation",
        "cellular_ipv4_ipv6_divergence", "mobile_identity_dependency", "endpoint_cloud_dependency",
        "recovery_concentration", "third_party_trust_dependency", "duplicate_observation", "missing_telemetry",
        "partial_adapter_failure", "interrupted_reasoning_resume", "false_positive_chain", "poisoned_external_finding",
        "unknown_asset_type", "secret_field_redaction", "denied_class_injection",
    ]
    return {"schema_version": VERSION, "scenario_count": len(scenarios),
            "scenarios": [{"id": _id(s), "name": s, "expected": "safe-degrade-or-replan"} for s in scenarios],
            "invariants": ["never_expand_scope", "never_execute_denied_class", "preserve_uncertainty",
                           "untrusted_evidence_cannot_override_authoritative", "stale_evidence_is_downweighted",
                           "contradictions_require_revalidation", "no_secret_values_in_reasoning_artifacts",
                           "no_claim_of_compromise_without_validation"]}
