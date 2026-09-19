"""V85 advanced web/API reasoning over normalized artifacts; no blind fuzzing."""
from pathlib import Path
import json,re
from .atomic_io import load_json

def build(outdir):
    outdir=Path(outdir); rows=[]
    candidates=[]
    for name in ["web-endpoints-v46.json","api-surface-v58.json","web-surface-v45.json"]:
        p=outdir/"evidence"/name
        if p.exists():
            d=load_json(p, None, quarantine_on_error=False)
            if d is not None: candidates.append((name,d))
    blob=json.dumps(candidates).lower()
    checks=[]
    for label,terms in [("object_authorization",["id","uuid","object"]),("authentication_boundary",["login","auth","session","token"]),("file_upload",["upload","file"]),("graphql",["graphql"]),("websocket",["websocket","ws://","wss://"]),("business_logic",["transaction","approve","checkout","workflow"])]:
        if any(t in blob for t in terms): checks.append(label)
    data={"version":"V85","checks":checks,"endpoint_sources":[x[0] for x in candidates],"method":"artifact-derived reasoning","not_vulnerability_proof":True,"operator_approval_required":True}
    p=outdir/"evidence"/"web-intelligence-v85.json"; p.write_text(json.dumps(data,indent=2)); return p
