from __future__ import annotations
import json, html
from pathlib import Path

def build(root,target):
 root=Path(root); e=root/'evidence'; reports=root/'reports'; reports.mkdir(exist_ok=True)
 files=sorted(p.name for p in e.glob('*.json')); body=''.join(f'<li>{html.escape(x)}</li>' for x in files)
 text=f'''<!doctype html><html><head><meta charset="utf-8"><title>Security Operator</title></head><body><h1>Security Operator V99</h1><p>Target: {html.escape(target)}</p><h2>Evidence artifacts</h2><ul>{body}</ul><p>Operator review remains required for consequential actions.</p></body></html>'''
 p=reports/'operator-dashboard-v99.html'; p.write_text(text); return p
