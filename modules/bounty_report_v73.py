"""V73 submission-ready bug bounty report drafts. Never fabricates impact/evidence."""
import json
from pathlib import Path

def build(outdir):
    outdir=Path(outdir); src=outdir/"evidence"/"bounty-triage-v72.json"
    items=[]
    if src.exists():
        try: items=json.loads(src.read_text()).get("findings",[])
        except (OSError, json.JSONDecodeError): pass
    lines=["# Bug Bounty Report Pack (V73)","","These are analyst drafts. No report is submitted automatically.",""]
    for f in items:
        lines += [f"## {f['id']}",f"- Reportability: {f['reportability']}","- Title: [ANALYST TO CONFIRM]","- Asset: [ANALYST TO CONFIRM]","- Steps to reproduce: [ANALYST TO DOCUMENT AUTHORIZED STEPS]","- Evidence: [REFERENCE VERIFIED EVIDENCE ONLY]","- Impact: [ANALYST TO ESTABLISH]","- Remediation: [ANALYST TO RECOMMEND]",""]
    p=outdir/"reports"/"bug-bounty-report-pack-v73.md"; p.write_text("\n".join(lines)); return p
