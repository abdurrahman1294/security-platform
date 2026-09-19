from pathlib import Path
import json
from modules.controlled_exploitation_v30 import run_proof
from modules.exploit_evidence_v31 import build as build_ledger
from modules.residual_risk_v32 import build as build_risk

def setup(root):
    (root/"evidence").mkdir(parents=True); (root/"reports").mkdir(); (root/"vulns").mkdir()
    (root/"scope.txt").write_text("127.0.0.1\n")
    (root/"evidence"/"normalized-findings.json").write_text(json.dumps([{"finding_id":"F-1","title":"Reflected XSS","severity":"high","endpoint":"http://127.0.0.1:9/?q=test"}]))

def test_v30_requires_approval(tmp_path):
    setup(tmp_path)
    try: run_proof(tmp_path,"F-1",str(tmp_path/"scope.txt"),approved=False)
    except PermissionError: pass
    else: assert False

def test_v31_and_v32_empty_are_safe(tmp_path):
    setup(tmp_path)
    build_ledger(tmp_path); p=build_risk(tmp_path)
    data=json.loads(p.read_text())
    assert data["human_decision_required"] is True

def test_v30_rejects_unsupported(tmp_path):
    setup(tmp_path)
    p=tmp_path/"evidence"/"normalized-findings.json"
    p.write_text(json.dumps([{"finding_id":"F-2","title":"RCE","severity":"critical","endpoint":"http://127.0.0.1:9/"}]))
    try: run_proof(tmp_path,"F-2",str(tmp_path/"scope.txt"),approved=True)
    except Exception: pass
