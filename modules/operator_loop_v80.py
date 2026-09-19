"""V80 bounded operator loop. Plans, observes state, and dispatches only registered safe builders."""
from pathlib import Path
import json
from .security_brain_v77 import build as brain
from .evidence_memory_v78 import build as memory
from .task_router_v79 import build as router

def build(outdir, mode, target, objective="general", execute=False):
    outdir=Path(outdir); brain(outdir,mode,target,objective); memory(outdir); router(outdir,mode,objective)
    data={"version":"V80","mode":mode,"target":target,"objective":objective,"execution_requested":bool(execute),
          "execution_policy":"plan-first; only registered capabilities; consequential actions require explicit operator approval",
          "loop":["observe","normalize","prioritize","propose","operator-approve","execute-safe-task","record","re-evaluate"],
          "next":"review evidence/task-router-v79.json and approve applicable tasks"}
    p=outdir/"evidence"/"operator-loop-v80.json"; p.write_text(json.dumps(data,indent=2)); (outdir/"reports"/"operator-loop-v80.md").write_text("# Operator Loop\n\nThe loop is bounded and auditable. Planning is automatic; consequential execution remains approval-gated.\n"); return p
