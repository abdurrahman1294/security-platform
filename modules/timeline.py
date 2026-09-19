#!/usr/bin/env python3
"""Create a lightweight engagement timeline from framework artifacts."""
from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path

def build_timeline(outdir: str | Path) -> Path:
    root=Path(outdir); events=[]
    state=root/"evidence"/"engagement-state.json"
    if state.exists():
        try:
            s=json.loads(state.read_text());
            for phase in s.get("completed",[]): events.append({"timestamp":s.get("last_updated"),"event":"phase_completed","phase":phase,"source":str(state.relative_to(root))})
        except json.JSONDecodeError: pass
    for rel, label in [("recon/subdomains.txt","recon_discovery"),("ports/nmap-detailed.nmap","port_enumeration"),("ports/nmap-top.nmap","port_enumeration"),("vulns/findings.json","vulnerability_scan"),("evidence/finding-status.json","finding_review"),("evidence/attack-graph.json","attack_graph"),("reports/report-pack.md","report_pack")]:
        p=root/rel
        if p.exists(): events.append({"timestamp":datetime.fromtimestamp(p.stat().st_mtime,timezone.utc).isoformat(),"event":label,"source":rel})
    events.sort(key=lambda e:e.get("timestamp") or "")
    payload={"schema_version":"1.0","event_count":len(events),"events":events}
    path=root/"evidence"/"timeline.json"; path.parent.mkdir(parents=True,exist_ok=True); path.write_text(json.dumps(payload,indent=2),encoding="utf-8")
    (root/"reports"/"timeline.md").write_text("# Engagement Timeline\n\n"+"\n".join(f"- `{e.get('timestamp','')}` — **{e['event']}** — `{e['source']}`" for e in events)+"\n",encoding="utf-8")
    return path
