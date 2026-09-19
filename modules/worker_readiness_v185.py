from __future__ import annotations
from pathlib import Path
import os
from .atomic_io import atomic_write_json

def build(root):
    root=Path(root); ev=root/'evidence'; ev.mkdir(parents=True,exist_ok=True)
    checks={'isolated_workdir':root.exists(),'job_identity':bool(os.environ.get('PENTEST_JOB_ID')),'central_evidence_ledger':(ev/'evidence-index.json').exists(),'execution_ledger':(ev/'tool-execution-ledger-v40.json').exists(),'atomic_state':(ev/'execution-state-v101.json').exists()}
    data={'schema_version':'185.1','checks':checks,'ready':all(checks.values()),'missing':[k for k,v in checks.items() if not v],'mode':'single-controller; worker execution requires explicit job identity'}
    atomic_write_json(ev/'worker-readiness-v185.json',data); return data
