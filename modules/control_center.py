from __future__ import annotations
import html,json
from .atomic_io import load_json
from pathlib import Path

def _load(p,d):
    return load_json(p, d)

def generate_control_center(outdir,client='',target=''):
    root=Path(outdir); ev=root/'evidence'; rep=root/'reports'
    graph=_load(ev/'attack-graph.json',{'nodes':[],'edges':[]}); assets=_load(ev/'assets.json',{'assets':[]}); pr=_load(ev/'assessment-priorities.json',{'recommendations':[]}); q=_load(ev/'validation-queue.json',{'queue':[]}); tl=_load(ev/'timeline.json',[])
    findings=[n for n in graph.get('nodes',[]) if n.get('type')=='finding']; sev={s:sum(str(n.get('severity','')).lower()==s for n in findings) for s in ('critical','high','medium','low','info')}
    vals=_load(ev/'validation-ledger.json',[]); ret=_load(ev/'retest-ledger.json',[])
    cards=[('Assets',len(assets.get('assets',[]))),('Findings',len(findings)),('Confirmed',sum(n.get('status')=='confirmed' for n in findings)),('Validations',len(vals)),('Retests',len(ret)),('Hypothesis edges',sum(e.get('status')=='hypothesis' for e in graph.get('edges',[])))]
    cards_html=''.join(f'<div class="card"><span>{html.escape(k)}</span><b>{v}</b></div>' for k,v in cards)
    rows=''.join('<tr>'+''.join(f'<td>{html.escape(str(v))}</td>' for v in [n.get('finding_id') or n.get('id'),n.get('label'),n.get('severity'),n.get('status'),n.get('asset'),n.get('confidence')])+'</tr>' for n in findings)
    recs=''.join(f'<li><b>{html.escape(str(r.get("finding_id")))}</b> — {html.escape(str(r.get("title")))} <small>{r.get("rank_score")}/100</small><br>{html.escape(str(r.get("reason")))}</li>' for r in pr.get('recommendations',[])[:10])
    qrows=''.join(f'<tr><td>{html.escape(str(x.get("finding_id")))}</td><td>{html.escape(str(x.get("title")))}</td><td>{x.get("rank_score")}</td><td>{html.escape(str(x.get("queue_status")))}</td></tr>' for x in q.get('queue',[])[:15])
    events=tl if isinstance(tl,list) else tl.get('events',[]); trows=''.join(f'<li><b>{html.escape(str(x.get("event","event")))}</b> — {html.escape(str(x.get("timestamp","")))} — {html.escape(str(x.get("detail",x.get("finding_id",""))))}</li>' for x in events[-20:])
    page=f'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Engagement Control Center</title><style>body{{font-family:system-ui,sans-serif;max-width:1400px;margin:auto;padding:24px;background:#fafafa}}.cards,.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px}}.card,.panel{{background:white;border:1px solid #ddd;border-radius:12px;padding:16px}}.card b{{display:block;font-size:30px}}.card span,small{{color:#666}}.panel{{margin-top:16px}}table{{width:100%;border-collapse:collapse}}th,td{{padding:8px;border-bottom:1px solid #eee;text-align:left}}.scroll{{overflow:auto}}</style></head><body><h1>Engagement Control Center</h1><p><b>Client:</b> {html.escape(client)} &nbsp; <b>Target:</b> {html.escape(target)}</p><div class="cards">{cards_html}</div><section class="panel"><h2>Risk Overview</h2><p>Critical {sev['critical']} · High {sev['high']} · Medium {sev['medium']} · Low {sev['low']} · Info {sev['info']}</p></section><div class="grid"><section class="panel"><h2>What Should I Investigate Next?</h2><ol>{recs or '<li>No recommendations yet.</li>'}</ol></section><section class="panel"><h2>Validation Queue</h2><div class="scroll"><table><tr><th>Finding</th><th>Title</th><th>Priority</th><th>Status</th></tr>{qrows or '<tr><td colspan="4">Empty</td></tr>'}</table></div></section></div><section class="panel"><h2>Findings</h2><div class="scroll"><table><tr><th>ID</th><th>Finding</th><th>Severity</th><th>Status</th><th>Asset</th><th>Confidence</th></tr>{rows or '<tr><td colspan="6">No structured findings.</td></tr>'}</table></div></section><section class="panel"><h2>Timeline</h2><ul>{trows or '<li>No timeline events.</li>'}</ul></section><p><small>Local self-contained dashboard. Recommendations are advisory; hypotheses require human validation.</small></p></body></html>'''
    rep.mkdir(parents=True,exist_ok=True); path=rep/'control-center.html'; path.write_text(page,encoding='utf-8'); return path
