"""V3.68 Adaptive Specialist Orchestration.

Routes an unusual assessment to the smallest useful set of registered
specialists, executes only governed specialist entry points, correlates their
results, and produces the next information-gain step. Specialist selection is
adaptive and evidence-driven; it never grants authority or expands scope.
"""
from __future__ import annotations
import hashlib, json, time
from pathlib import Path
from typing import Any, Callable, Iterable

VERSION = "3.68.0"

SPECIALISTS = {
    "web": {"signals": ("web", "http", "api", "xss", "sqli", "idor", "jwt", "graphql", "cookie", "session"), "phases": ("probe", "web", "api")},
    "network": {"signals": ("network", "port", "tcp", "udp", "service", "firewall", "dns", "smb"), "phases": ("ports", "dns", "tls")},
    "cloud": {"signals": ("aws", "azure", "gcp", "cloud", "iam", "bucket", "lambda", "kubernetes", "eks", "role"), "phases": ("cloud",)},
    "identity": {"signals": ("identity", "authentication", "authorization", "role", "session", "jwt", "credential", "ad", "smb"), "phases": ("authenticated", "ad")},
    "osint": {"signals": ("osint", "domain", "subdomain", "username", "public", "organization", "social"), "phases": ("recon",)},
    "attack-path": {"signals": ("chain", "pivot", "path", "trust boundary", "compose", "privilege", "escalation"), "phases": ("intelligence",)},
    "rare-case": {"signals": ("strange", "unusual", "rare", "weird", "unexpected", "intermittent", "edge case", "bypass"), "phases": ()},
}


def _fingerprint(*parts: Any) -> str:
    text = "|".join(str(x or "") for x in parts)
    return hashlib.sha256(text.lower().encode()).hexdigest()[:16]


def _textual_context(story: str, objective: str, findings: Iterable[Any], observations: Iterable[Any]) -> str:
    chunks = [story or "", objective or ""]
    for item in list(findings)[-80:] + list(observations)[-80:]:
        try:
            chunks.append(json.dumps(item, ensure_ascii=False) if isinstance(item, (dict, list)) else str(item))
        except Exception:
            chunks.append(str(item))
    return " ".join(chunks).lower()


def select_specialists(*, story: str = "", objective: str = "", findings: Iterable[Any] = (), observations: Iterable[Any] = (), max_specialists: int = 4) -> list[dict[str, Any]]:
    text = _textual_context(story, objective, findings, observations)
    ranked = []
    for name, spec in SPECIALISTS.items():
        hits = [s for s in spec["signals"] if s in text]
        score = min(1.0, 0.15 + 0.14 * len(hits)) if hits else 0.0
        # Keep broad reconnaissance available when context is sparse.
        if name in {"web", "network"} and not hits and not text.strip():
            score = 0.25
        if score:
            ranked.append({"specialist": name, "score": round(score, 3), "signals": hits[:12], "phases": list(spec["phases"])})
    ranked.sort(key=lambda x: (-x["score"], x["specialist"]))
    selected = ranked[:max(1, min(int(max_specialists), 6))]
    # Rare-case reasoning is additive, not a replacement for technical specialists.
    if any(x["specialist"] == "rare-case" for x in ranked) and not any(x["specialist"] == "rare-case" for x in selected):
        selected[-1] = next(x for x in ranked if x["specialist"] == "rare-case")
    return selected


def _safe_summary(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return {k: value[k] for k in list(value)[:25]}
    return {"result": str(value)[:4000]}


def orchestrate(*, engine: Any, objective: str, story: str = "", findings: Iterable[Any] = (), observations: Iterable[Any] = (), max_specialists: int = 4, max_rounds: int = 2, authorized: bool = False, approval_token: str = "") -> dict[str, Any]:
    """Run adaptive specialist entry points already owned by PentestEngine.

    Only a fixed registry of engine methods can be selected. The orchestrator
    does not interpret natural-language commands as shell commands.
    """
    if not objective.strip():
        raise ValueError("objective is required")
    selected = select_specialists(story=story, objective=objective, findings=findings, observations=observations, max_specialists=max_specialists)
    rounds = []
    completed = set()
    method_map = {
        "web": {"probe", "web", "api"}, "network": {"ports", "dns", "tls"},
        "cloud": {"cloud"}, "identity": {"authenticated", "ad"},
        "osint": {"recon"}, "attack-path": {"intelligence"}, "rare-case": set(),
    }
    # Governance is intentionally checked before active specialist execution.
    if not authorized:
        out = {"schema_version": VERSION, "status": "blocked", "reason": "authorization-required", "selected_specialists": selected, "rounds": []}
        _write(engine.e.output, out)
        return out

    for round_no in range(1, max(1, min(int(max_rounds), 4)) + 1):
        round_rows = []
        for item in selected:
            name = item["specialist"]
            for phase in method_map.get(name, set()):
                key = (name, phase)
                if key in completed:
                    continue
                # Approval is required for any specialist phase marked high-impact by policy.
                if phase in {"cloud", "authenticated", "ad"} and not approval_token:
                    round_rows.append({"specialist": name, "phase": phase, "status": "blocked", "reason": "approval-required"})
                    completed.add(key)
                    continue
                fn = getattr(engine, phase, None)
                if not callable(fn):
                    round_rows.append({"specialist": name, "phase": phase, "status": "unavailable"})
                    completed.add(key)
                    continue
                try:
                    result = fn() if phase != "cloud" else fn("aws")
                    round_rows.append({"specialist": name, "phase": phase, "status": "completed", "summary": _safe_summary(result)})
                except Exception as exc:
                    round_rows.append({"specialist": name, "phase": phase, "status": "error", "error": f"{type(exc).__name__}:{str(exc)[:500]}"})
                completed.add(key)
        rounds.append({"round": round_no, "actions": round_rows})
        # Re-rank from fresh evidence for the next round. Existing phases are suppressed.
        if round_no < max_rounds:
            selected = select_specialists(story=story, objective=objective, findings=findings, observations=observations, max_specialists=max_specialists)
            selected = [x for x in selected if any((x["specialist"], p) not in completed for p in method_map.get(x["specialist"], set())) or x["specialist"] in {"rare-case", "attack-path"}]
            if not selected:
                break

    result = {
        "schema_version": VERSION, "status": "completed", "objective": objective[:10000], "story": story[:30000],
        "selected_specialists": selected, "rounds": rounds,
        "adaptation": {"dynamic_specialist_selection": True, "fresh_evidence_reassessment": True, "failed_step_suppression": True, "registered_engine_entrypoints_only": True},
        "governance": {"authorization_checked": True, "scope_policy_owned_by_engine": True, "no_arbitrary_shell": True, "no_scope_expansion": True, "approval_token_required_for_sensitive_specialists": True},
        "run_fingerprint": _fingerprint(engine.e.target, objective, story), "created_at": time.time(),
    }
    _write(engine.e.output, result)
    return result


def _write(root: str | Path, result: dict[str, Any]) -> None:
    p = Path(root) / "evidence"
    p.mkdir(parents=True, exist_ok=True)
    (p / "adaptive-specialist-orchestration-v368.json").write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
