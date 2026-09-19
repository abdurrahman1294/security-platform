"""V72 Bug bounty finding triage and duplicate/reportability intelligence."""
import json, re
from modules.findings_io import load_findings_file
from pathlib import Path

def _findings(outdir):
    vals=[]
    for p in [Path(outdir)/"vulns"/"nuclei.txt", Path(outdir)/"evidence"/"normalized-findings.json", Path(outdir)/"evidence"/"findings.json"]:
        if not p.exists(): continue
        try:
            if p.suffix == ".json":
                vals.extend(load_findings_file(p))
            else:
                vals.extend({"raw":l} for l in p.read_text(errors="ignore").splitlines() if l.strip())
        except (OSError, UnicodeError):
            continue
    return vals

def build(outdir):
    outdir=Path(outdir); findings=_findings(outdir); tri=[]; seen=set()
    for i,f in enumerate(findings):
        raw=json.dumps(f,sort_keys=True) if isinstance(f,dict) else str(f)
        key=re.sub(r"\W+"," ",raw.lower())[:240]
        dup=key in seen; seen.add(key)
        tri.append({"id":f"BB-{i+1:04d}","duplicate_candidate":dup,"confidence":"low" if dup else "needs-review","reportability":"review-required","evidence_reference":str(f.get("template-id",f.get("raw",""))) if isinstance(f,dict) else str(f)[:240]})
    data={"version":"V72","count":len(tri),"findings":tri,"submission_policy":"never auto-submit","notes":["Do not infer a bounty acceptance decision from scanner output.","Confirm program policy and reproduce safely before submission."]}
    p=outdir/"evidence"/"bounty-triage-v72.json"; p.write_text(json.dumps(data,indent=2))
    (outdir/"reports"/"bounty-triage-v72.md").write_text("# Bug Bounty Triage\n\nFindings: %d\n\nAll reportability decisions require analyst review and program-policy confirmation.\n"%len(tri))
    return p
