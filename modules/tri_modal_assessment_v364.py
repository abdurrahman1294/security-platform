"""V3.64 tri-modal assessment controller.

Three complementary operating modes:
  python      - deterministic Python/toolchain first
  ai          - AI reasoning first; registered tools may be invoked through the governed executor
  hybrid      - Python observes/builds evidence, AI reasons over the evidence, then Python executes

The modes do not delete capabilities from either side. The AI can consume an
operator narrative and generate its own hypotheses when the narrative is thin.
Execution still passes through the platform's scope/authorization/tool gates.
"""
from __future__ import annotations
import json, os, time
from pathlib import Path
from typing import Any

VERSION = "3.64.0"


def load_operator_story(path: str | Path | None = None, story: str = "") -> str:
    if story.strip():
        return story.strip()
    if path:
        p = Path(path)
        if p.is_file():
            return p.read_text(encoding="utf-8", errors="ignore")[:30000].strip()
    return ""


def collect_observations(root: str | Path) -> list[dict[str, Any]]:
    root = Path(root); out=[]
    for p in sorted((root / "evidence").glob("*.json")):
        try:
            obj=json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        out.append({"artifact":p.name,"data":obj})
    return out[-80:]


def run_python_mode(engine, phases: tuple[str, ...], *, authorize: bool = False) -> dict[str, Any]:
    """Use the existing Python engine at full configured capability."""
    return engine.run(phases, require_authorization=not authorize)


def run_ai_mode(engine, *, objective: str, story: str = "", execute: bool = True,
                max_cycles: int = 3, approval_token: str = "", authorized: bool = False) -> dict[str, Any]:
    """AI-first reasoning, followed by the governed registered-tool executor."""
    from modules.ai_offensive_agent_v363 import run_reasoning
    from modules.agentic_executor_v363 import execute_actions
    from security_platform.core.tools import inventory
    allowed=[x.name for x in inventory() if x.status == "ready"]
    observations=collect_observations(engine.e.output)
    completed=[]; cycles=[]
    for cycle in range(max(1, min(int(max_cycles), 5))):
        reasoning=run_reasoning(root=engine.e.output, target=engine.e.target,
            objective=objective, operator_story=story, observations=observations,
            findings=[], completed_actions=completed, allowed_tools=allowed,
            in_scope=engine.policy.contains, authorized=authorized,
            approval_token=approval_token)
        plan=reasoning["validated_plan"]["accepted"]
        if not execute or not plan:
            cycles.append({"cycle":cycle+1,"reasoning":reasoning,"executed":0})
            break
        execution=execute_actions(engine.e.output, plan, target=engine.e.target,
            in_scope=engine.policy.contains, authorized=authorized,
            approval_token=approval_token, max_actions=4)
        completed.extend(execution["receipts"])
        observations.extend(execution["receipts"][-12:])
        cycles.append({"cycle":cycle+1,"reasoning":reasoning,"execution":execution})
    result={"schema_version":VERSION,"mode":"ai","status":"completed",
            "objective":objective,"operator_story_present":bool(story.strip()),
            "cycles":cycles,"evidence":str(engine.e.output/"evidence"/"tri-modal-v364.json")}
    (engine.e.output/"evidence").mkdir(parents=True,exist_ok=True)
    (engine.e.output/"evidence"/"tri-modal-v364.json").write_text(json.dumps(result,indent=2),encoding="utf-8")
    return result


def run_hybrid_mode(engine, *, objective: str, story: str = "", python_phases: tuple[str,...] = ("recon","probe","ports","web"),
                    max_cycles: int = 3, approval_token: str = "", authorized: bool = False) -> dict[str, Any]:
    """Python gathers broad evidence; AI reasons over it; Python executes approved registered actions."""
    py=run_python_mode(engine, python_phases, authorize=authorized)
    ai=run_ai_mode(engine, objective=objective, story=story, execute=True,
                   max_cycles=max_cycles, approval_token=approval_token, authorized=authorized)
    result={"schema_version":VERSION,"mode":"hybrid","status":"completed",
            "python":py,"ai":ai,
            "operator_story_present":bool(story.strip()),
            "design":{"python_first":True,"ai_reasoning":True,"shared_evidence":True,
                       "adaptive_feedback":True,"registered_tool_execution":True}}
    (engine.e.output/"evidence"/"tri-modal-v364.json").write_text(json.dumps(result,indent=2),encoding="utf-8")
    return result
