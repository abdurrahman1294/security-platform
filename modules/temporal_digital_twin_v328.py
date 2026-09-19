"""V3.28 temporal attack-path and digital-twin reasoning fabric.

Models environmental state over time and evaluates governed validation plans.
It intentionally does not generate weaponized payloads.  Payload assurance is
limited to benign, observable proof markers and lab/testbed adapters whose
contracts require explicit authorization and approval before consequential
execution.
"""
from __future__ import annotations
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable
import hashlib, json, time

VERSION = "3.28.0"
DENIED = {
    "credential_theft", "phishing", "unrestricted_rce", "persistence",
    "covert_c2", "real_data_exfiltration", "uncontrolled_propagation",
    "destructive_impact", "carrier_bypass", "credential_spraying_at_scale",
}

SAFE_PAYLOAD_CLASSES = {
    "http_marker": "Benign unique marker for proving reflection/reachability.",
    "header_probe": "Non-mutating request for security-control verification.",
    "protocol_probe": "Bounded protocol conformance request without state-changing data.",
    "lab_proof": "Fixed loopback/testbed proof marker; never emitted as an unrestricted exploit.",
}


def _id(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def _write(root: str | Path, name: str, obj: Any) -> Path:
    p = Path(root) / "evidence" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")
    return p


def normalize_timeline(events: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    out = []
    for i, raw in enumerate(events or []):
        if not isinstance(raw, dict):
            continue
        clean = {k: v for k, v in raw.items() if k.lower() not in {
            "password", "secret", "token", "private_key", "credential", "cookie", "session_cookie"
        }}
        ts = clean.get("timestamp", clean.get("observed_at", i))
        try: order = float(ts)
        except (TypeError, ValueError): order = float(i)
        out.append({
            "id": str(clean.get("id", f"event-{i+1}")),
            "timestamp": ts,
            "order": order,
            "asset": str(clean.get("asset", clean.get("target", "unknown"))),
            "state": str(clean.get("state", clean.get("claim", "unknown"))),
            "source": str(clean.get("source", "unknown")),
            "trust": str(clean.get("trust", clean.get("provenance", "unknown"))),
            "tags": clean.get("tags", []) if isinstance(clean.get("tags", []), list) else [],
        })
    return sorted(out, key=lambda x: (x["order"], x["id"]))


def build_temporal_states(events: list[dict[str, Any]], assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    asset_ids = [str(a.get("id")) for a in assets if a.get("id")]
    states = []
    active: dict[str, dict[str, Any]] = {a: {"status": "unknown"} for a in asset_ids}
    for e in events:
        asset = e["asset"]
        active.setdefault(asset, {})
        active[asset]["status"] = e["state"]
        states.append({"at": e["timestamp"], "event_id": e["id"], "snapshot": json.loads(json.dumps(active))})
    return states


def compare_states(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    changes = []
    keys = sorted(set(before) | set(after))
    for k in keys:
        if before.get(k) != after.get(k):
            changes.append({"asset": k, "before": before.get(k), "after": after.get(k)})
    return {"change_count": len(changes), "changes": changes}


def build_temporal_attack_paths(chains: list[dict[str, Any]], states: list[dict[str, Any]], limit: int = 20) -> list[dict[str, Any]]:
    paths = []
    for c in chains[:limit]:
        possible_windows = []
        chain_nodes = {str(x) for x in c.get("chain", [])}
        if len(states) >= 2:
            for i in range(len(states) - 1):
                left = states[i].get("snapshot", {})
                right = states[i+1].get("snapshot", {})
                touched = set(left) | set(right)
                if chain_nodes and not (chain_nodes & touched):
                    continue
                possible_windows.append({"from": states[i]["at"], "to": states[i+1]["at"], "event_ids": [states[i]["event_id"], states[i+1]["event_id"]], "chain_relevant": bool(chain_nodes & touched)})
        paths.append({
            "id": _id(c.get("chain_id", ""), "temporal"),
            "chain": c.get("chain", []),
            "base_priority": c.get("priority", 0),
            "temporal_windows": possible_windows,
            "temporal_confidence": round(min(1.0, 0.25 + 0.1 * len(possible_windows)), 4),
            "required_revalidation": "Validate every state transition before treating the path as currently reachable.",
        })
    return paths


def payload_assurance_catalog() -> list[dict[str, Any]]:
    return [
        {"id": k, "class": k, "description": v, "execution": "bounded-proof-only", "can_target_real_system": True, "requires": ["authorized_scope", "operator_approval_if_consequential"]}
        for k, v in SAFE_PAYLOAD_CLASSES.items()
    ]


def validate_payload_request(payload_class: str, target: str, *, authorized: bool, approved: bool, lab: bool = False) -> dict[str, Any]:
    allowed = payload_class in SAFE_PAYLOAD_CLASSES
    return {
        "allowed": bool(allowed and authorized and (approved or not lab)),
        "payload_class": payload_class,
        "target": target,
        "reason": "bounded benign proof" if allowed else "payload class is not supported",
        "governance": {"authorized": authorized, "approved": approved, "lab": lab, "unrestricted_exploit_generation": False},
    }


def build_v328_fabric(root: str | Path, *, target: str, assets: list[dict[str, Any]],
                      chains: list[dict[str, Any]] | None = None,
                      timeline: Iterable[dict[str, Any]] | None = None,
                      objective: str = "temporal-self-assessment") -> dict[str, Any]:
    events = normalize_timeline(timeline)
    states = build_temporal_states(events, assets)
    temporal_paths = build_temporal_attack_paths(chains or [], states)
    payloads = payload_assurance_catalog()
    result = {
        "schema_version": VERSION, "status": "ready", "target": target, "objective": objective,
        "timeline": events, "state_snapshots": states, "temporal_attack_paths": temporal_paths,
        "payload_assurance": {
            "mode": "bounded-proof-only", "catalog": payloads,
            "explicitly_not_provided": sorted(DENIED),
            "principle": "prove exploitability with the least-impact observable proof; do not generate unrestricted weaponized payloads",
        },
        "digital_twin": {
            "enabled": True, "mode": "state-model-and-what-if",
            "supports": ["before_after", "perspective_comparison", "control-change_impact", "temporal_window_analysis"],
            "does_not": ["autonomous_real_world_exploitation", "scope_expansion", "secret_capture"],
        },
        "governance": {"scope_locked": True, "authorization_required": True, "consequential_actions_require_approval": True},
        "created_at": time.time(),
    }
    _write(root, "temporal-digital-twin-v328.json", result)
    return result


def v328_test_matrix() -> dict[str, Any]:
    scenarios = [
        "state_change_invalidates_prior_finding", "attack_path_only_valid_in_old_window",
        "cellular_ipv4_ipv6_state_divergence", "perspective_state_mismatch", "control_change_breaks_chain",
        "control_change_enables_new_chain", "recovery_dependency_drift", "mobile_identity_state_drift",
        "endpoint_cloud_session_expiry", "third_party_integration_change", "contradictory_timeline",
        "missing_timestamp", "duplicate_event", "untrusted_state_transition", "scope_change_mid_mission",
        "authorization_revoked_mid_mission", "interrupted_twin_run", "resume_from_snapshot",
        "benign_payload_marker_only", "unrestricted_payload_request_denied", "secret_field_redaction",
        "destructive_payload_request_denied", "carrier_bypass_denied", "propagation_denied", "real_exfiltration_denied",
    ]
    return {"schema_version": VERSION, "scenario_count": len(scenarios),
            "scenarios": [{"id": _id(x), "name": x, "expected": "safe-degrade-or-deny"} for x in scenarios],
            "invariants": ["state_changes_trigger_revalidation", "never_expand_scope", "never_generate_denied_payloads", "no_secret_values", "preserve_uncertainty"]}
