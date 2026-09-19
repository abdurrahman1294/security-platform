"""V82 final intelligence pack: one operator-facing view of the engagement."""
from pathlib import Path
import json
from .atomic_io import load_json

def build(outdir):
    outdir=Path(outdir); rows=[]
    for p in sorted((outdir/"evidence").glob("*.json")):
        d=load_json(p, None, quarantine_on_error=False)
        if isinstance(d,dict): rows.append({"artifact":p.name,"version":d.get("version"),"mode":d.get("mode"),"status":d.get("status","generated")})
    payload={"version":"V82","artifact_count":len(rows),"artifacts":rows,"operator_summary":{"automation":"high","consequential_actions":"approval-gated","secret_collection":"disabled-by-design"},"closure":"requires human review"}
    ep=outdir/"evidence"/"final-intelligence-v82.json"; ep.write_text(json.dumps(payload,indent=2));
    (outdir/"reports"/"final-intelligence-v82.md").write_text("# Final Intelligence\n\nArtifacts indexed: %d\n\nAutomation is high, while consequential actions and final conclusions remain human-reviewed.\n"%len(rows)); return ep
