"""V242 final reality/readiness gate.

Separates three things that are often confused: code quality, capability
availability, and evidence-backed assessment completion.  A passing gate
never means "no vulnerabilities"; it means the requested workflow is
actually executable and its evidence/coverage requirements are satisfied.
"""
from __future__ import annotations

from pathlib import Path
from .atomic_io import atomic_write_json, load_json
from .tool_manager_v40 import TOOLS
from .tool_adapter_hardening_v162 import executable_path, verify_executable_identity

REQUIRED_CORE = (
    "engagement.json",
    "assets.json",
    "evidence-index.json",
    "execution-state-v101.json",
    "qa-verification-v103.json",
    "tool-capabilities-v213.json",
    "coverage-blindspots-v223.json",
    "quality-gate-v225.json",
    "research-exhaustion-v241.json",
)


def _tool_status(tool_id):
    try:
        path = executable_path(tool_id)
        if path is None:
            return {"tool": tool_id, "status": "unavailable-or-rejected"}
        ok, reason = verify_executable_identity(tool_id, path)
        return {"tool": tool_id, "status": "ready" if ok else "identity-failed", "path": str(path), "detail": reason}
    except (OSError, RuntimeError, ValueError) as exc:
        return {"tool": tool_id, "status": "error", "detail": str(exc)}


def build(root, target="", require_active_tools=False):
    root = Path(root)
    ev = root / "evidence"
    ev.mkdir(parents=True, exist_ok=True)
    checks = []
    for name in REQUIRED_CORE:
        checks.append({"check": name, "ok": (ev / name).is_file(), "detail": "present" if (ev / name).is_file() else "missing"})

    tools = [_tool_status(t) for t in TOOLS]
    ready_tools = [x["tool"] for x in tools if x["status"] == "ready"]
    if require_active_tools:
        checks.append({"check": "registered-toolchain", "ok": bool(ready_tools), "detail": ready_tools})

    q225 = load_json(ev / "quality-gate-v225.json", {})
    checks.append({
        "check": "production-quality-gate",
        "ok": q225.get("decision") == "PASS",
        "detail": q225.get("decision", "missing"),
    })

    blockers = [c["check"] for c in checks if not c["ok"]]
    decision = "READY_FOR_OPERATOR_REVIEW" if not blockers else "NOT_READY"
    data = {
        "schema_version": "242.0",
        "target": target,
        "decision": decision,
        "checks": checks,
        "toolchain": tools,
        "ready_tool_count": len(ready_tools),
        "blockers": blockers,
        "completion_claim_policy": "Never claim vulnerability-free or complete merely because scanners ran. Completion requires evidence-backed coverage and human review.",
        "human_review_required": True,
    }
    atomic_write_json(ev / "final-readiness-v242.json", data)
    report = root / "reports"
    report.mkdir(parents=True, exist_ok=True)
    lines = ["# Final Reality / Readiness Gate (V242)", "", f"Decision: **{decision}**", "", f"Registered tools ready: **{len(ready_tools)}/{len(TOOLS)}**", ""]
    lines.append("## Blockers")
    lines.extend([f"- {x}" for x in blockers] or ["- None"])
    lines += ["", "## Policy", "- This gate measures execution/readiness and evidence quality.", "- It does not prove an application is vulnerability-free.", "- Human validation remains mandatory for consequential findings and custom business logic."]
    (report / "final-readiness-v242.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return data
