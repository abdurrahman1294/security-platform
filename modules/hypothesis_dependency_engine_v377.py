"""V3.77 Evidence-Guided Hypothesis Persistence & Dependency Engine.

Turns mission context into explicit, evidence-seeking hypotheses and tracks the
smallest governed dependency needed to test them. Hypotheses are not findings.
No dependency can grant authority or expand scope.
"""
from __future__ import annotations
import hashlib, json, time
from pathlib import Path
from typing import Any

VERSION = "3.77.0"

HYPOTHESIS_RULES = [
    {
        "id": "access-control-object-id",
        "signals": ("different data for two roles", "object ids change", "object id", "role", "endpoint behaves strangely", "authorization", "idor", "access control"),
        "title": "Possible object-level access-control inconsistency",
        "class": "access-control",
        "priority": 1.0,
        "test": "Compare the same in-scope object identifiers across the two authorized roles and record response status/body differences.",
        "phase": "authenticated",
        "dependencies": ["authenticated-session", "crawled-url-artifact"],
    },
    {
        "id": "api-role-differential",
        "signals": ("api returns different data", "two roles", "different data", "role differential", "endpoint"),
        "title": "Possible role-dependent API behavior",
        "class": "authorization",
        "priority": 0.9,
        "test": "Replay an in-scope API request under each authorized role and compare response semantics.",
        "phase": "authenticated",
        "dependencies": ["authenticated-session", "crawled-url-artifact"],
    },
    {
        "id": "parser-representation-disagreement",
        "signals": ("strange", "unexpected", "different representation", "parser", "encoding", "normalization", "bypass"),
        "title": "Possible parser or representation disagreement",
        "class": "input-handling",
        "priority": 0.7,
        "test": "Use a bounded representation-differential test on an already in-scope input and compare normalized versus raw observations.",
        "phase": "web",
        "dependencies": ["live-web-artifact"],
    },
]

DEPENDENCIES = {
    "authenticated-session": {
        "description": "An operator-approved authenticated session/token is available to the governed authenticated scanner.",
        "phase": "authenticated", "sensitive": True,
    },
    "crawled-url-artifact": {
        "description": "A non-empty in-scope crawled URL artifact exists for API/authenticated testing.",
        "phase": "api", "sensitive": False,
    },
    "live-web-artifact": {
        "description": "A verified live-web/probe artifact exists for targeted web testing.",
        "phase": "probe", "sensitive": False,
    },
}


def _fp(*parts: Any) -> str:
    return hashlib.sha256("|".join(str(x or "") for x in parts).lower().encode()).hexdigest()[:16]


def _text(*parts: Any) -> str:
    vals = []
    for p in parts:
        if isinstance(p, (dict, list)):
            vals.append(json.dumps(p, ensure_ascii=False))
        else:
            vals.append(str(p or ""))
    return " ".join(vals).lower()


def _artifact_names(evidence: list[dict[str, Any]]) -> set[str]:
    out = set()
    for row in evidence:
        for name in row.get("evidence_artifacts", []) or []:
            out.add(str(name))
    return out


def _dependency_state(dep_id: str, *, evidence: list[dict[str, Any]], blocked_phases: set[str], available_phases: set[str]) -> dict[str, Any]:
    dep = DEPENDENCIES[dep_id]
    artifacts = _artifact_names(evidence)
    if dep_id == "authenticated-session":
        if "authenticated" in available_phases and any("authenticated" in str(x.get("phase", "")) for x in evidence):
            state = "satisfied"
            reason = "verified authenticated evidence exists"
        elif "authenticated" in blocked_phases:
            state = "blocked"
            reason = "authenticated phase requires operator approval token"
        else:
            state = "missing"
            reason = "no verified authenticated evidence"
    elif dep_id == "crawled-url-artifact":
        matches = {x for x in artifacts if "urls" in x.lower() and "web" in x.lower()}
        if matches:
            state, reason = "satisfied", "verified crawled URL artifact exists"
        elif "api" in blocked_phases:
            state, reason = "blocked", "API phase is waiting for a crawled URL artifact"
        else:
            state, reason = "missing", "no verified crawled URL artifact"
    elif dep_id == "live-web-artifact":
        if any(x.get("phase") == "probe" for x in evidence):
            state, reason = "satisfied", "verified probe evidence exists"
        else:
            state, reason = ("blocked", "web probe did not produce verified evidence") if "probe" in blocked_phases else ("missing", "no verified probe evidence")
    else:
        state, reason = "missing", "dependency not observed"
    return {"id": dep_id, "state": state, "reason": reason, "description": dep["description"], "phase": dep["phase"], "sensitive": dep["sensitive"]}


def build_state(*, objective: str, story: str, evidence: list[dict[str, Any]], actions: list[dict[str, Any]], prior: dict[str, Any] | None = None) -> dict[str, Any]:
    text = _text(objective, story)
    blocked_phases = {str(x.get("phase")) for x in actions if x.get("status") in {"blocked", "unavailable", "skipped"}}
    available_phases = {str(x.get("phase")) for x in evidence if x.get("evidence_produced")}
    hypotheses = []
    seen = set()
    for rule in HYPOTHESIS_RULES:
        hits = [s for s in rule["signals"] if s in text]
        if not hits:
            continue
        if rule["id"] in seen:
            continue
        deps = [_dependency_state(d, evidence=evidence, blocked_phases=blocked_phases, available_phases=available_phases) for d in rule["dependencies"]]
        unresolved = [d for d in deps if d["state"] != "satisfied"]
        blocked = [d for d in unresolved if d["state"] == "blocked"]
        status = "supported-by-context" if not unresolved else "evidence-gap"
        if blocked:
            status = "blocked-pending-evidence"
        hypotheses.append({
            "id": rule["id"], "title": rule["title"], "class": rule["class"],
            "priority": rule["priority"], "status": status, "context_signals": hits[:8],
            "test": rule["test"], "required_phase": rule["phase"],
            "dependencies": deps,
            "evidence_required_before_finding": True,
            "is_finding": False,
        })
        seen.add(rule["id"])

    # Preserve hypotheses from an earlier artifact when the current context is sparse.
    for old in (prior or {}).get("hypotheses", []):
        if isinstance(old, dict) and old.get("id") and old["id"] not in seen:
            carry = dict(old)
            carry["persistence"] = "carried-forward"
            hypotheses.append(carry)

    unresolved = [h for h in hypotheses if h.get("status") != "resolved"]
    candidates = []
    for h in sorted(unresolved, key=lambda x: (-float(x.get("priority", 0)), x.get("id", ""))):
        unsat = [d for d in h.get("dependencies", []) if d.get("state") != "satisfied"]
        # The first unsatisfied dependency determines the operator-facing next step.
        dep = unsat[0] if unsat else None
        candidates.append({
            "hypothesis_id": h["id"], "priority": h.get("priority", 0),
            "next_test": h.get("test"), "required_phase": h.get("required_phase"),
            "dependency": dep,
            "actionability": "blocked" if dep and dep.get("state") == "blocked" else "ready" if not dep else "missing-input",
        })

    blocked = [c for c in candidates if c.get("actionability") == "blocked"]
    status = "blocked_pending_evidence" if blocked else "ready_for_targeted_test" if candidates else "no_unresolved_hypotheses"
    return {
        "schema_version": VERSION,
        "status": status,
        "hypotheses": hypotheses,
        "high_value_next_tests": candidates[:5],
        "blocked_dependencies": blocked[:5],
        "finding_rule": "A hypothesis never becomes a finding from context alone; verified evidence is required.",
        "persistence": {"enabled": True, "prior_loaded": bool(prior), "hypotheses_carried_forward": sum(1 for h in hypotheses if h.get("persistence") == "carried-forward")},
        "created_at": time.time(),
        "fingerprint": _fp(objective, story),
    }


def load_prior(root: Path) -> dict[str, Any] | None:
    path = root / "evidence" / "hypothesis-dependency-v377.json"
    try:
        return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None
    except (OSError, ValueError):
        return None


def write_state(root: Path, state: dict[str, Any]) -> None:
    ev = root / "evidence"
    ev.mkdir(parents=True, exist_ok=True)
    (ev / "hypothesis-dependency-v377.json").write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
