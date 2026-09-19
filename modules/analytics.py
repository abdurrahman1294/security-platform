from __future__ import annotations
import json
from .atomic_io import load_json
from pathlib import Path
from datetime import datetime,timezone

def _load(p,d):
    return load_json(p, d)

def build_analytics(outdir):
    root=Path(outdir); ev=root/'evidence'; rep=root/'reports'; g=_load(ev/'attack-graph.json',{'nodes':[],'edges':[]}); fs=[n for n in g.get('nodes',[]) if n.get('type')=='finding']; vals=_load(ev/'validation-ledger.json',[]); rets=_load(ev/'retest-ledger.json',[]); assets=_load(ev/'assets.json',{'assets':[]}).get('assets',[])
    sev={s:sum(str(n.get('severity','')).lower()==s for n in fs) for s in ('critical','high','medium','low','info')}; statuses={}
    for n in fs: statuses[n.get('status','unknown')]=statuses.get(n.get('status','unknown'),0)+1
    conf=round(sum(float(n.get('confidence',0) or 0) for n in fs)/len(fs),3) if fs else 0
    m={'schema_version':'1.0','generated_at':datetime.now(timezone.utc).isoformat(),'assets':len(assets),'findings':len(fs),'severity':sev,'statuses':statuses,'confirmed':sum(n.get('status')=='confirmed' for n in fs),'average_confidence':conf,'confirmation_rate':round(sum(n.get('status')=='confirmed' for n in fs)/len(fs),3) if fs else 0,'validations_recorded':len(vals),'retests_recorded':len(rets),'hypothesis_edges':sum(e.get('status')=='hypothesis' for e in g.get('edges',[]))}
    (ev/'analytics.json').write_text(json.dumps(m,indent=2),encoding='utf-8'); lines=['# Assessment Analytics','','## Metrics','',f"- Assets: **{m['assets']}**",f"- Findings: **{m['findings']}**",f"- Confirmed: **{m['confirmed']}**",f"- Confirmation rate: **{m['confirmation_rate']*100:.1f}%**",f"- Average confidence: **{conf:.3f}**",f"- Controlled validations: **{len(vals)}**",f"- Retest records: **{len(rets)}**",f"- Hypothesis edges: **{m['hypothesis_edges']}**",'','## Severity distribution','']+[f'- {k.title()}: **{v}**' for k,v in sev.items()]+['','> Metrics summarize recorded artifacts and do not independently prove compromise or impact.']; rep.mkdir(parents=True,exist_ok=True); (rep/'analytics.md').write_text('\n'.join(lines)+'\n',encoding='utf-8'); return ev/'analytics.json'
