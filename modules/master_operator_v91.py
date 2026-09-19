"""V91 master operator state: synthesizes V77-V90 into one auditable state."""
from pathlib import Path
import json
from .atomic_io import load_json

def build(outdir, mode, target):
    outdir=Path(outdir); names=["security-brain-v77.json","evidence-memory-v78.json","task-router-v79.json","operator-loop-v80.json","unified-assessment-v81.json","final-intelligence-v82.json","ai-reasoning-v83.json","target-profile-v84.json","web-intelligence-v85.json","osint-collection-v86.json","cross-engagement-memory-v87.json","bounty-prioritization-v88.json","reporting-monitoring-v89.json","security-training-v90.json"]
    present=[]
    for n in names:
        p=outdir/"evidence"/n
        if p.exists():
            d=load_json(p, None, quarantine_on_error=False)
            present.append({"artifact":n,"keys":sorted(d.keys()) if isinstance(d,dict) else []})
    data={"version":"V91","mode":mode,"target":target,"stack":"V77-V91","components_present":present,"component_count":len(present),"decision":"operator_review_required","autonomy_boundary":["no credential theft","no persistence","no lateral movement","no exfiltration","no destructive actions","no unrestricted exploitation","no arbitrary shell"],"next_step":"review task router, AI reasoning, target profile and evidence before approving any consequential action"}
    p=outdir/"evidence"/"master-operator-v91.json"; p.write_text(json.dumps(data,indent=2))
    (outdir/"reports"/"master-operator-v91.md").write_text("# Master Security Operator\n\nStack: **V77–V91**\n\nComponents available: %d\n\nThe master state is a synthesis layer; it does not grant additional execution privileges.\n"%len(present))
    return p
