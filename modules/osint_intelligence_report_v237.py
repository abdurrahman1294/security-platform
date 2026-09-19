"""V237 OSINT intelligence synthesis from collected evidence."""
from __future__ import annotations
from pathlib import Path
from .atomic_io import atomic_write_json, load_json

def build(root, target=""):
    root=Path(root); ev=root/'evidence'; corr=load_json(ev/'osint-correlation-v235.json',{}); gaps=load_json(ev/'osint-gap-analysis-v236.json',{})
    high=[e for e in corr.get('entities',[]) if e.get('confidence')=='high']
    provisional=[e for e in corr.get('entities',[]) if e.get('confidence')!='high']
    out={"schema_version":"237.0","target":target,"high_confidence_entities":high,"provisional_entities":provisional,"coverage":gaps,"limitations":["public-source visibility is incomplete","absence of evidence is not evidence of absence","source availability and terms may change"],"analyst_review_required":True}
    atomic_write_json(ev/'osint-intelligence-v237.json',out)
    report=root/'reports'; report.mkdir(parents=True,exist_ok=True)
    (report/'osint-intelligence-v237.md').write_text("# OSINT Intelligence Report\n\nTarget: `%s`\n\nCoverage: %s%%\n\nHigh-confidence entities: %d\n\nProvisional entities: %d\n\nAnalyst review is required before attribution or operational conclusions.\n"%(target,gaps.get('coverage_percent',0),len(high),len(provisional)),encoding='utf-8')
    return out
