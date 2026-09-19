"""V240 bug-bounty coverage, evidence and submission quality gate."""
from __future__ import annotations
from pathlib import Path
from .atomic_io import atomic_write_json, load_json

def build(root):
    root=Path(root); ev=root/'evidence'
    plan=load_json(ev/'bug-bounty-plan-v239.json',{}); tri=load_json(ev/'bounty-triage-v72.json',{}); qa=load_json(ev/'qa-verification-v103.json',{})
    planned=sum(len(x.get('tests',[])) for x in plan.get('plan',[])); findings=len(tri.get('findings',[]))
    evidence_ok=bool(load_json(ev/'evidence-index.json',{})) or any(ev.glob('*evidence*'))
    blockers=[]
    if not plan.get('assets'): blockers.append('no scoped assets in bounty plan')
    if not planned: blockers.append('no assessment tests planned')
    if not evidence_ok: blockers.append('no evidence index detected')
    out={"schema_version":"240.0","planned_test_count":planned,"triaged_finding_count":findings,"evidence_present":evidence_ok,"qa_present":bool(qa),"blockers":blockers,"decision":"PASS" if not blockers else "REVIEW","submission":"never automatic","completion_rule":"PASS means process quality is sufficient for analyst review, not that the application is vulnerability-free"}
    atomic_write_json(ev/'bug-bounty-quality-v240.json',out)
    report=root/'reports'; report.mkdir(parents=True,exist_ok=True)
    (report/'bug-bounty-quality-v240.md').write_text("# Bug Bounty Quality Gate\n\nDecision: **%s**\n\nPlanned tests: %d\nTriaged findings: %d\nEvidence present: %s\n\nBlockers:\n%s\n"%(out['decision'],planned,findings,evidence_ok,"\n".join('- '+x for x in blockers) if blockers else '- None'),encoding='utf-8')
    return out
