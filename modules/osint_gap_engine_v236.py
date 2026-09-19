"""V236 OSINT coverage and gap analysis."""
from __future__ import annotations
from pathlib import Path
from .atomic_io import atomic_write_json, load_json

DIMENSIONS=["infrastructure","web","code","documents","organization","social","media","images","history"]
KEYWORDS={"infrastructure":["domain","host","ip","dns","asn","certificate"],"web":["http","url","endpoint","robots","sitemap"],"code":["github","gitlab","repository","package"],"documents":["pdf","document","report"],"organization":["company","organization","registry"],"social":["profile","social"],"media":["news","press"],"images":["image","photo"],"history":["archive","historical","wayback"]}

def build(root):
    root=Path(root); ev=root/'evidence'; corr=load_json(ev/'osint-correlation-v235.json',{}); rows=corr.get('entities',[])
    gaps=[]
    for dim, terms in KEYWORDS.items():
        hits=sum(1 for r in rows if any(t in str(r.get('value','')).lower() for t in terms))
        gaps.append({"dimension":dim,"evidence_items":hits,"status":"covered" if hits else "gap","next_action":"expand source collection" if not hits else "corroborate and deepen"})
    covered=sum(x['status']=='covered' for x in gaps); coverage=round(covered/len(DIMENSIONS)*100,1)
    out={"schema_version":"236.0","coverage_percent":coverage,"dimensions":gaps,"completion_rule":"never declare complete while material dimensions remain uninvestigated"}
    atomic_write_json(ev/'osint-gap-analysis-v236.json',out); return out
