"""V81 unified assessment controller: orchestrates existing platform layers by mode."""
from pathlib import Path
import json
from .intelligence_modes_v76 import build as modes
from .complete_assessment_v63_v70 import build as complete

def build(outdir, mode, target, client, objective="general", program="", policy="", complete_requested=False):
    outdir=Path(outdir); modules=[]
    if mode in ("pentest","auto") and complete_requested:
        try: complete(outdir,client,target); modules.append("V63-V70")
        except TypeError: pass
    modes(outdir,mode,target,objective,program,policy); modules.append("V71-V76")
    data={"version":"V81","mode":mode,"target":target,"client":client,"objective":objective,"modules":modules,
          "controller":"unified-assessment","human_review_required":True}
    p=outdir/"evidence"/"unified-assessment-v81.json"; p.write_text(json.dumps(data,indent=2)); (outdir/"reports"/"unified-assessment-v81.md").write_text("# Unified Assessment\n\nMode: %s\n\nIntegrated intelligence layers: %s\n"%(mode,", ".join(modules))); return p
