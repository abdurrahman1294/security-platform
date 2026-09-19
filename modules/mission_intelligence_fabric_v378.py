"""V3.78 Mission Intelligence Fabric.

Comprehensive integration layer for governed offensive assessment:
- durable hypothesis -> dependency -> next-test state
- evidence graph and provenance
- hypothesis -> exploitation bridge
- adaptive retry/reassessment planning
- coverage-gap and specialist prioritization
- operator approval queue
- convergence/readiness decisioning
- resumable mission fingerprinting

This layer plans and coordinates existing governed engine entry points. It never
creates authority, expands scope, translates free text to shell, or performs
unbounded offensive actions.
"""
from __future__ import annotations
import hashlib, json, time
from pathlib import Path
from typing import Any

VERSION = "3.78.0"


def _sha(*values: Any) -> str:
    value = values if len(values) != 1 else values[0]
    raw = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str).encode()
    return hashlib.sha256(raw).hexdigest()[:20]


def _read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else default
    except (OSError, ValueError, TypeError):
        return default


def _evidence_inventory(root: Path) -> list[dict[str, Any]]:
    ev = root / "evidence"
    rows: list[dict[str, Any]] = []
    if not ev.is_dir():
        return rows
    for p in sorted(ev.rglob("*")):
        if not p.is_file() or p.name.startswith("."):
            continue
        try:
            data = p.read_bytes()
            if not data:
                continue
            rows.append({"name": str(p.relative_to(ev)), "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        except OSError:
            continue
    return rows


def build_evidence_graph(root: Path) -> dict[str, Any]:
    inventory = _evidence_inventory(root)
    nodes = []
    for item in inventory:
        name = item["name"]
        kind = "tool-artifact"
        if "finding" in name.lower() or "vuln" in name.lower(): kind = "finding-artifact"
        elif "conversation" in name.lower() or "reason" in name.lower() or "hypothesis" in name.lower(): kind = "reasoning-artifact"
        nodes.append({"id": _sha(name, item["sha256"]), "type": kind, **item})
    edges = []
    # Provenance edges are conservative: artifacts co-existing in one evidence
    # set are related, never automatically corroborating.
    for a, b in zip(nodes, nodes[1:]):
        edges.append({"source": a["id"], "target": b["id"], "relation": "same-engagement-provenance", "corroborates": False})
    return {"schema_version": VERSION, "generated_at": time.time(), "nodes": nodes, "edges": edges,
            "corroboration_rule": "Shared storage or execution does not constitute independent corroboration."}


def exploit_bridge(hypothesis_state: dict[str, Any], root: Path) -> dict[str, Any]:
    """Convert hypotheses into bounded proof-oriented exploitation candidates.

    The bridge only selects existing governed technique classes. It does not
    generate arbitrary payloads or execute an exploit.
    """
    mapping = {
        "access-control": ("idor-access-control", "Compare authorized role/object access with controlled identifiers."),
        "authorization": ("idor-access-control", "Compare authorized role responses for the same in-scope object."),
        "input-handling": ("xss-reflection", "Run a bounded representation-differential validation against an in-scope input."),
    }
    candidates = []
    for h in hypothesis_state.get("hypotheses", []):
        if not isinstance(h, dict) or h.get("status") == "resolved":
            continue
        technique = mapping.get(str(h.get("class")))
        if not technique:
            continue
        candidates.append({
            "hypothesis_id": h.get("id"), "technique_class": technique[0],
            "proof_goal": technique[1], "priority": h.get("priority", 0),
            "requires_verified_evidence": True, "execution_mode": "governed-existing-capability",
            "finding_claim": False,
        })
    result = {"schema_version": VERSION, "candidates": sorted(candidates, key=lambda x: (-float(x.get("priority", 0)), str(x.get("hypothesis_id")))),
              "execution_policy": "candidate generation only; existing scope/authorization/approval gates remain authoritative"}
    return result


def adaptive_plan(*, objective: str, story: str, hypothesis_state: dict[str, Any], evidence_graph: dict[str, Any], recent_actions: list[dict[str, Any]]) -> dict[str, Any]:
    actions = []
    for candidate in hypothesis_state.get("high_value_next_tests", [])[:5]:
        dep = candidate.get("dependency") or {}
        actionability = candidate.get("actionability")
        actions.append({
            "priority": candidate.get("priority", 0),
            "hypothesis_id": candidate.get("hypothesis_id"),
            "next_test": candidate.get("next_test"),
            "required_phase": candidate.get("required_phase"),
            "actionability": actionability,
            "blocked_reason": dep.get("reason") if actionability == "blocked" else None,
            "operator_action": "approve/prepare dependency" if actionability == "blocked" else "execute governed targeted test",
        })
    failed = [x for x in recent_actions if x.get("status") in {"failed", "partial"}]
    retries = []
    for x in failed[:5]:
        retries.append({"phase": x.get("phase"), "reason": x.get("outcome_detail"),
                        "strategy": "reassess prerequisites and retry only after state/evidence changes", "automatic_retry": False})
    return {"schema_version": VERSION, "objective": objective, "story": story,
            "next_tests": actions, "recovery_plan": retries,
            "evidence_nodes": len(evidence_graph.get("nodes", [])),
            "replanning_rule": "New evidence or dependency-state change triggers re-ranking."}


def coverage_gaps(root: Path, hypothesis_state: dict[str, Any]) -> dict[str, Any]:
    evidence = {x["name"].lower() for x in _evidence_inventory(root)}
    domains = {
        "recon": any("recon" in x or "subdomain" in x for x in evidence),
        "web": any("web" in x or "probe" in x or "http" in x for x in evidence),
        "network": any("nmap" in x or "naabu" in x or "port" in x for x in evidence),
        "api": any("api" in x or "crawl" in x or "url" in x for x in evidence),
        "identity": any("auth" in x or "identity" in x for x in evidence),
        "cloud": any("aws" in x or "cloud" in x for x in evidence),
    }
    gaps = [k for k, present in domains.items() if not present]
    high = [h.get("id") for h in hypothesis_state.get("hypotheses", []) if h.get("status") in {"evidence-gap", "blocked-pending-evidence"}]
    return {"schema_version": VERSION, "domains": domains, "uncovered_domains": gaps,
            "hypothesis_driven_gaps": high, "coverage_is_not_vulnerability_proof": True}


def operator_queue(hypothesis_state: dict[str, Any], root: Path) -> list[dict[str, Any]]:
    queue = []
    for item in hypothesis_state.get("blocked_dependencies", [])[:5]:
        dep = item.get("dependency") or {}
        queue.append({"type": "approval-or-prerequisite", "priority": item.get("priority", 0),
                      "hypothesis_id": item.get("hypothesis_id"), "dependency": dep.get("id"),
                      "request": dep.get("reason"), "authority_change": False})
    return queue


def mission_state(*, root: Path, client: str, target: str, scope: str, objective: str, story: str,
                  hypothesis_state: dict[str, Any], recent_actions: list[dict[str, Any]]) -> dict[str, Any]:
    graph = build_evidence_graph(root)
    bridge = exploit_bridge(hypothesis_state, root)
    plan = adaptive_plan(objective=objective, story=story, hypothesis_state=hypothesis_state, evidence_graph=graph, recent_actions=recent_actions)
    gaps = coverage_gaps(root, hypothesis_state)
    queue = operator_queue(hypothesis_state, root)
    blocked = bool(queue)
    unresolved = [h for h in hypothesis_state.get("hypotheses", []) if h.get("status") != "resolved"]
    if blocked and unresolved:
        status = "blocked_pending_evidence"
    elif unresolved:
        status = "ready_for_targeted_test"
    else:
        status = "converged"
    state = {
        "schema_version": VERSION, "status": status, "generated_at": time.time(),
        "mission_fingerprint": _sha(client, target, scope, objective, story),
        "objective": objective, "story": story,
        "hypothesis": hypothesis_state, "evidence_graph": graph, "exploitation_bridge": bridge,
        "adaptive_plan": plan, "coverage": gaps, "operator_queue": queue,
        "recent_actions": recent_actions[-20:],
        "decision": {
            "why": "blocked dependencies" if blocked else "unresolved evidence-seeking hypotheses" if unresolved else "no unresolved hypotheses",
            "finding_claims": "none without verified evidence",
            "scope_expansion": False, "authority_grant": False,
        },
    }
    return state


def write(root: Path, state: dict[str, Any]) -> None:
    ev = root / "evidence"; ev.mkdir(parents=True, exist_ok=True)
    (ev / "mission-intelligence-v378.json").write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
