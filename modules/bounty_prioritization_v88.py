"""V88 bug-bounty prioritization using evidence quality, impact and program policy."""
from pathlib import Path
import json
from modules.findings_io import load_findings_file

def build(outdir):
    outdir=Path(outdir); findings=[]
    sources = [outdir/"evidence"/"normalized-findings.json", outdir/"vulns"/"findings.json", outdir/"evidence"/"bounty-triage-v72.json"]
    for p in sources:
        if not p.exists():
            continue
        try:
            if p.name == "bounty-triage-v72.json":
                data=json.loads(p.read_text(errors="ignore"))
                rows=data.get("findings", []) if isinstance(data, dict) else []
            else:
                rows=load_findings_file(p)
            findings.extend(x for x in rows if isinstance(x, dict))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
    scores=[]
    for i,d in enumerate(findings,1):
        sev=str(d.get("severity","medium")).lower() if isinstance(d,dict) else "medium"
        base={"critical":95,"high":85,"medium":65,"low":40,"info":20}.get(sev,50)
        conf=20 if isinstance(d,dict) and d.get("confidence") in ("high","confirmed") else 10
        evidence=10 if isinstance(d,dict) and d.get("evidence") else 0
        scores.append({"finding_ref":d.get("id",f"finding-{i}") if isinstance(d,dict) else f"finding-{i}","priority":min(100,base+conf+evidence),"reason":"impact + confidence + evidence quality","requires_manual_review":True})
    scores.sort(key=lambda x:x["priority"],reverse=True)
    data={"version":"V88","priorities":scores,"auto_submission":False,"duplicate_review":True,"policy_must_be_respected":True}
    p=outdir/"evidence"/"bounty-prioritization-v88.json"; p.write_text(json.dumps(data,indent=2)); return p
