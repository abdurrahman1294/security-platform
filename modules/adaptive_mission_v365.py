"""V3.65 mission coordinator: Python, AI, or Hybrid."""
from __future__ import annotations
import json, time
from pathlib import Path
from typing import Any
from modules.offensive_brain_v365 import run_brain
from modules.tri_modal_assessment_v364 import run_python_mode, run_ai_mode

VERSION="3.65.0"


def run_mission(engine, mode: str, *, objective: str, story: str = "", phases=None,
                max_cycles: int = 4, approval_token: str = "", authorized: bool = False) -> dict[str,Any]:
    mode=mode.lower().strip()
    phases=tuple(phases or ("recon","probe","ports","web"))
    root=engine.e.output
    result={"schema_version":VERSION,"mode":mode,"started_at":time.time(),"objective":objective}
    if mode == "python":
        result["python"]=run_python_mode(engine, phases, authorize=authorized)
    elif mode == "ai":
        result["brain"]=run_brain(root=root,target=engine.e.target,objective=objective,story=story,max_cycles=max_cycles)
        result["ai"]=run_ai_mode(engine,objective=objective,story=story,execute=True,max_cycles=max_cycles,approval_token=approval_token,authorized=authorized)
    elif mode == "hybrid":
        result["python"]=run_python_mode(engine, phases, authorize=authorized)
        result["brain_before"]=run_brain(root=root,target=engine.e.target,objective=objective,story=story,max_cycles=max_cycles)
        result["ai"]=run_ai_mode(engine,objective=objective,story=story,execute=True,max_cycles=max_cycles,approval_token=approval_token,authorized=authorized)
        result["brain_after"]=run_brain(root=root,target=engine.e.target,objective=objective,story=story,max_cycles=max_cycles)
    else:
        raise ValueError("mode must be python, ai, or hybrid")
    result["finished_at"]=time.time()
    (root/"evidence").mkdir(parents=True,exist_ok=True)
    (root/"evidence"/"adaptive-mission-v365.json").write_text(json.dumps(result,indent=2,sort_keys=True),encoding="utf-8")
    return result
