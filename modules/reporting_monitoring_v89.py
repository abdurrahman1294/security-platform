"""V89 reporting and continuous-monitoring assessment layer."""
from __future__ import annotations
from pathlib import Path
from .atomic_io import atomic_write_json

def build(outdir, target):
    outdir=Path(outdir); evidence=outdir/'evidence'; reports=outdir/'reports'; evidence.mkdir(parents=True,exist_ok=True); reports.mkdir(parents=True,exist_ok=True)
    evidence_files=list(evidence.glob('*.json')); report_files=list(reports.glob('*'))
    triggers=[]
    names=' '.join(p.name.lower() for p in evidence_files)
    if 'asset' in names or 'subdomain' in names: triggers.append('new_asset_or_subdomain')
    if 'endpoint' in names: triggers.append('new_endpoint')
    if 'technology' in names: triggers.append('technology_change')
    if 'finding' in names: triggers.append('new_or_changed_finding')
    data={'version':'V89.1','target':target,'report_sections':['executive_summary','scope','methodology','attack_surface','findings','evidence','risk','business_impact','remediation','retest','limitations','appendices'],'monitoring_triggers':['new_subdomain','new_certificate','new_endpoint','technology_change','new_finding','finding_status_change'],'observed_triggers':sorted(set(triggers)),'evidence_files':len(evidence_files),'report_files':len(report_files),'auto_submission':False,'decision':'MONITORING_READY' if evidence_files else 'WAITING_FOR_EVIDENCE'}
    atomic_write_json(evidence/'reporting-monitoring-v89.json',data)
    (reports/'monitoring-plan-v89.md').write_text('# Continuous Monitoring Plan\n\nTarget: %s\n\nObserved monitoring signals: %s\n\nReassessment remains scope- and policy-gated.\n' % (target, ', '.join(triggers) if triggers else 'none yet'),encoding='utf-8')
    return evidence/'reporting-monitoring-v89.json'
