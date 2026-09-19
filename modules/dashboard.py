#!/usr/bin/env python3
"""Generate a self-contained local engagement dashboard."""
from __future__ import annotations
import html, json
from pathlib import Path

def generate_dashboard(outdir: str | Path, client: str, target: str) -> Path:
    root=Path(outdir); gp=root/"evidence"/"attack-graph.json"; ap=root/"evidence"/"assets.json"; np=root/"evidence"/"next-investigation.json"
    graph=json.loads(gp.read_text()) if gp.exists() else {"nodes":[],"edges":[]}; assets=json.loads(ap.read_text()) if ap.exists() else {"assets":[]}; nxt=json.loads(np.read_text()) if np.exists() else {"recommendations":[]}
    findings=[n for n in graph.get("nodes",[]) if n.get("type")=="finding"]
    counts={s:sum(1 for n in findings if n.get("severity")==s) for s in ["critical","high","medium","low","info"]}
    confirmed=sum(1 for n in findings if n.get("status")=="confirmed"); hypotheses=sum(1 for e in graph.get("edges",[]) if e.get("status")=="hypothesis")
    cards=[("Assets",len(assets.get("assets",[]))),("Findings",len(findings)),("Confirmed",confirmed),("Hypothesis edges",hypotheses)]
    cards_html="".join(f'<div class="card"><div>{html.escape(k)}</div><strong>{v}</strong></div>' for k,v in cards)
    rows="".join(f'<tr><td>{html.escape(str(n.get("finding_id") or n.get("id")))}</td><td>{html.escape(str(n.get("label")))}</td><td>{html.escape(str(n.get("severity")))}</td><td>{html.escape(str(n.get("status")))}</td><td>{html.escape(str(n.get("asset")))}</td></tr>' for n in findings)
    recs="".join(f'<li><b>{html.escape(str(r.get("finding_id")))}</b> — {html.escape(str(r.get("title")))} <small>(score {r.get("rank_score")})</small><br>{html.escape(str(r.get("reason")))}</li>' for r in nxt.get("recommendations",[])[:10])
    page=f'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Engagement Dashboard</title><style>body{{font-family:system-ui,sans-serif;max-width:1200px;margin:2rem auto;padding:0 1rem}}.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:1rem}}.card{{padding:1rem;border:1px solid #ddd;border-radius:12px}}.card strong{{font-size:2rem}}table{{width:100%;border-collapse:collapse}}td,th{{padding:.6rem;border-bottom:1px solid #ddd;text-align:left}}.panel{{margin:2rem 0}}li{{margin:.8rem 0}}</style></head><body><h1>Security Assessment Dashboard</h1><p><b>Client:</b> {html.escape(client)} &nbsp; <b>Target:</b> {html.escape(target)}</p><div class="cards">{cards_html}</div><div class="panel"><h2>Severity</h2><p>Critical {counts['critical']} · High {counts['high']} · Medium {counts['medium']} · Low {counts['low']} · Info {counts['info']}</p></div><div class="panel"><h2>What Should I Investigate Next?</h2><ol>{recs or '<li>No recommendations yet.</li>'}</ol></div><div class="panel"><h2>Findings</h2><table><tr><th>ID</th><th>Finding</th><th>Severity</th><th>Status</th><th>Asset</th></tr>{rows or '<tr><td colspan="5">No structured findings.</td></tr>'}</table></div><p><small>Generated for authorized assessment use. Hypotheses require manual validation.</small></p></body></html>'''
    path=root/"reports"/"dashboard.html"; path.parent.mkdir(parents=True,exist_ok=True); path.write_text(page,encoding="utf-8"); return path
