from __future__ import annotations
from pathlib import Path
from .atomic_io import atomic_write_json, load_json

def build(root):
    root=Path(root); ev=root/'evidence'; ev.mkdir(parents=True,exist_ok=True)
    ledger=load_json(ev/'tool-execution-ledger-v40.json',[]); state=load_json(ev/'execution-state-v101.json',{})
    completed=sum(r.get('status')=='completed' for r in ledger if isinstance(r,dict)); failed=sum(r.get('status') in {'failed','error','timeout'} for r in ledger if isinstance(r,dict))
    tasks=state.get('tasks',{}) if isinstance(state,dict) else {}
    finding_count=0
    for p in (root/'vulns'/'findings.json', ev/'normalized-findings.json'):
        if p.exists():
            try:
                from .findings_io import load_findings_file
                finding_count += len(load_findings_file(p))
            except (OSError, ValueError):
                pass
    total=completed+failed; success_rate=round(completed/total,3) if total else None
    health='healthy' if total==0 or success_rate>=0.9 else 'degraded' if success_rate>=0.5 else 'blocked'
    data={'schema_version':'171.1','metrics':{'tool_runs':len(ledger),'tool_success_rate':success_rate,'failed_tool_runs':failed,'queue_depth':sum(t.get('status')=='pending' for t in tasks.values()) if isinstance(tasks,dict) else 0,'artifact_count':sum(1 for p in ev.rglob('*') if p.is_file()),'finding_count':finding_count,'task_count':len(tasks) if isinstance(tasks,dict) else 0},'health_state':health}
    atomic_write_json(ev/'platform-observability-v171.json',data); return data
