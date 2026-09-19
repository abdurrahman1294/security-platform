#!/usr/bin/env python3
"""Generate a self-contained operator workspace for an engagement."""
from __future__ import annotations
import html,json
from .atomic_io import load_json
from pathlib import Path

def _load(p,d):
    return load_json(p,d)

def generate(root: str|Path, client="", target="") -> Path:
    root=Path(root); ev=root/"evidence"; rep=root/"reports"; rep.mkdir(parents=True,exist_ok=True)
    manifest=_load(ev/"engagement.json",{}); kb=_load(ev/"knowledge-base.json",{"entities":[],"relations":[]}); inv=_load(ev/"investigation-priorities-v18.json",{"recommendations":[]}); queue=_load(ev/"validation-queue.json",{"queue":[]}); analytics=_load(ev/"analytics.json",{})
    findings=[e for e in kb.get("entities",[]) if e.get("type")=="finding"]; assets=[e for e in kb.get("entities",[]) if e.get("type")=="asset"]
    cards=[("Assets",len(assets)),("Findings",len(findings)),("Relations",len(kb.get("relations",[]))),("Validation queue",len(queue.get("queue",[])))]
    cardhtml="".join(f'<div class="card"><span>{html.escape(k)}</span><b>{v}</b></div>' for k,v in cards)
    recs="".join(f'<li><b>{html.escape(str(r.get("finding_id")))}</b> — {html.escape(str(r.get("title")))} <strong>{r.get("priority")}/100</strong><br><small>{html.escape(str(r.get("recommended_action")))}</small></li>' for r in inv.get("recommendations",[])[:10])
    rows="".join(f'<tr><td>{html.escape(str(f.get("key")))}</td><td>{html.escape(str((f.get("properties") or {}).get("label")))}</td><td>{html.escape(str((f.get("properties") or {}).get("severity")))}</td><td>{html.escape(str((f.get("properties") or {}).get("status")))}</td></tr>' for f in findings)
    page=f'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Operator Workspace</title><style>body{{font-family:system-ui,sans-serif;margin:0;background:#f4f6f8;color:#17202a}}header{{padding:24px;background:#fff;border-bottom:1px solid #ddd;position:sticky;top:0}}main{{max-width:1400px;margin:auto;padding:20px}}.cards,.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:14px}}.card,.panel{{background:#fff;border:1px solid #ddd;border-radius:12px;padding:16px}}.card b{{display:block;font-size:30px;margin-top:4px}}.card span,small{{color:#667085}}.panel{{margin-top:16px}}table{{width:100%;border-collapse:collapse}}th,td{{padding:9px;border-bottom:1px solid #eee;text-align:left}}.scroll{{overflow:auto}}a{{text-decoration:none}}nav a{{margin-right:14px}}</style></head><body><header><h1>Engagement Operator Workspace</h1><p><b>Client:</b> {html.escape(str(client or manifest.get('client','')))} &nbsp; <b>Target:</b> {html.escape(str(target or manifest.get('target','')))}</p><nav><a href="#next">Next investigation</a><a href="#findings">Findings</a><a href="control-center.html">Control Center</a><a href="dashboard.html">Dashboard</a></nav></header><main><div class="cards">{cardhtml}</div><section id="next" class="panel"><h2>What Should I Investigate Next?</h2><ol>{recs or '<li>No priorities available. Refresh assessment intelligence first.</li>'}</ol></section><section id="findings" class="panel"><h2>Findings</h2><div class="scroll"><table><tr><th>ID</th><th>Finding</th><th>Severity</th><th>Status</th></tr>{rows or '<tr><td colspan="4">No findings.</td></tr>'}</table></div></section><section class="panel"><h2>Operator Guidance</h2><p>Use Controlled Validation for authorized verification. Hypotheses remain hypotheses until supported by evidence. This workspace provides decision support and does not execute exploitation or lateral movement.</p></section></main></body></html>'''
    p=rep/"operator-workspace.html"; p.write_text(page,encoding="utf-8"); return p
