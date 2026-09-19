"""V84 intelligent target profiling from existing evidence only."""
from pathlib import Path
import json,re
from .atomic_io import load_json

def build(outdir,target):
    outdir=Path(outdir); text=""; files=[]
    for p in (outdir/"evidence").glob("*.json"):
        try: text += p.read_text(errors="ignore")[:12000].lower(); files.append(p.name)
        except (OSError, UnicodeError): pass
    tech=[]
    for x in ["react","next.js","node","express","django","flask","php","laravel","nginx","apache","graphql","aws","azure","gcp","kubernetes"]:
        if x in text: tech.append(x)
    surfaces=[]
    mapping={"web":"http","api":"api","authentication":"auth","cloud":"cloud","identity":"iam","infrastructure":"port","business_logic":"workflow"}
    for k,v in mapping.items():
        if v in text or k in text: surfaces.append(k)
    if not surfaces: surfaces=["web","api","infrastructure"]
    priorities=[]
    if "api" in surfaces: priorities += ["api_authorization","object_access","input_validation"]
    if "authentication" in surfaces: priorities += ["session_lifecycle","account_recovery","role_transitions"]
    if "business_logic" in surfaces: priorities += ["workflow_state_transitions","transaction_integrity"]
    data={"version":"V84","target":target,"technologies":sorted(set(tech)),"surfaces":sorted(set(surfaces)),"priority_areas":list(dict.fromkeys(priorities)),"source_artifacts":files,"evidence_only":True}
    p=outdir/"evidence"/"target-profile-v84.json"; p.write_text(json.dumps(data,indent=2)); return p
