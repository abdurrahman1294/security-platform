"""V76 unified operator modes: pentest, bug bounty, OSINT, auto."""
from pathlib import Path
import json
from .bug_bounty_v71 import build as bounty_program
from .bounty_triage_v72 import build as bounty_triage
from .bounty_report_v73 import build as bounty_report
from .osint_v74 import build as osint_plan
from .osint_graph_v75 import build as osint_graph

def build(outdir, mode, seed, objective="general", program="", policy_file=""):
    outdir=Path(outdir)
    mode=mode.lower()
    result={"version":"V76","mode":mode,"operator_approval_required":True,"modules":[]}
    if mode in ("bugbounty","auto"):
        bounty_program(outdir,program,policy_file,[seed]); bounty_triage(outdir); bounty_report(outdir); result["modules"] += ["V71","V72","V73"]
    if mode in ("osint","auto"):
        osint_plan(outdir,seed,objective); osint_graph(outdir); result["modules"] += ["V74","V75"]
    if mode in ("pentest","auto"):
        result["modules"] += ["V1-V70-existing"]
    p=outdir/"evidence"/"intelligence-mode-v76.json"; p.write_text(json.dumps(result,indent=2)); return p
