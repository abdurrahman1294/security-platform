"""V3.4 report-pack builder from existing evidence."""
from __future__ import annotations
import json
from pathlib import Path

def build(root: str|Path,target: str="")->dict:
    root=Path(root); rep=root/"reports"; rep.mkdir(parents=True,exist_ok=True)
    summaries=[]
    for p in sorted((root/"evidence").glob("*.json")):
        try:
            d=json.loads(p.read_text(encoding="utf-8")); summaries.append((p.name,d))
        except (OSError,json.JSONDecodeError,UnicodeDecodeError): pass
    findings=[]
    for _,d in summaries:
        if isinstance(d,dict) and isinstance(d.get("findings"),list): findings.extend(d["findings"])
    md=["# Security Assessment Report","",f"Target: `{target}`","","## Evidence-backed summary","",f"Evidence JSON artifacts: **{len(summaries)}**",f"Observed finding records: **{len(findings)}**","","## Important interpretation","","Findings are reported with their observed/suspected state. Confirmation requires appropriate validation and operator review.","","## Evidence inventory",""]
    md += [f"- `{name}`" for name,_ in summaries]
    (rep/"assessment-report-v34.md").write_text("\n".join(md)+"\n",encoding="utf-8")
    return {"status":"completed","report":str(rep/"assessment-report-v34.md"),"evidence_artifacts":len(summaries),"finding_records":len(findings)}
