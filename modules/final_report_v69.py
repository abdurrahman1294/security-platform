from __future__ import annotations
import json
from pathlib import Path
from modules.findings_io import load_findings_file

def build(root,client,target):
    root=Path(root); ev=root/'evidence'; rp=root/'reports'; ev.mkdir(exist_ok=True); rp.mkdir(exist_ok=True)
    docs=sorted(str(p.relative_to(root)) for p in rp.glob('*.md'))
    findings=[]
    for rel in ['vulns/findings.json','vulns/authenticated-findings.json','evidence/normalized-findings-v24.json']:
        findings.extend(load_findings_file(root/rel))
    data={'schema_version':'1.0','version':'V69','client':client,'target':target,'report_count':len(docs),'finding_count':len(findings),'reports':docs,'human_review_required':True}
    (ev/'final-assessment-summary-v69.json').write_text(json.dumps(data,indent=2))
    text=f'''# Final Assessment Summary\n\n**Client:** {client}\n\n**Target:** {target}\n\n## Assessment lifecycle\n\nDiscover → Normalize → Deduplicate → Correlate → Understand → Prioritize → Controlled Validate → Controlled Proof → Evidence → Risk → Remediate → Retest → Close → Report\n\n## Findings\n\nObserved/recorded finding items: **{len(findings)}**\n\n## Review status\n\nThis summary is an orchestration index. Findings, proof decisions, remediation, retest and closure require human review.\n'''
    (rp/'final-assessment-summary-v69.md').write_text(text)
    return ev/'final-assessment-summary-v69.json',rp/'final-assessment-summary-v69.md'
