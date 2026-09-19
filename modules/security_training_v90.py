"""V90 training/lab mode: turns observed concepts into safe learning plans."""
from pathlib import Path
import json

def build(outdir, objective="general"):
    outdir=Path(outdir); obj=objective.lower(); topics=[]
    for key,topic in [("idor","object-level authorization"),("xss","cross-site scripting"),("auth","authentication and session security"),("api","API security"),("workflow","business logic and workflows"),("osint","passive OSINT and source correlation")]:
        if key in obj: topics.append(topic)
    if not topics: topics=["reconnaissance","web/API security","authentication","authorization","business logic","evidence and reporting"]
    stages=["concept","safe lab","recon","detection","manual validation","evidence","reporting","reflection"]
    data={"version":"V90","objective":objective,"topics":topics,"stages":stages,"real_target_execution":False,"purpose":"training and lab practice"}
    p=outdir/"evidence"/"security-training-v90.json"; p.write_text(json.dumps(data,indent=2)); return p
