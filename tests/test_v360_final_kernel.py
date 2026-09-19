from pathlib import Path
from modules.autonomous_kernel_v360 import AutonomousKernel
from modules.final_capability_closure_v360 import build_final_closure, v360_test_matrix

def test_lease_approval_and_convergence(tmp_path: Path):
    k=AutonomousKernel(tmp_path)
    base=dict(action="web_crawl",target="127.0.0.1",risk="R1",basis=["missing:web"],scope_hash="scope1",authorization_epoch="auth1")
    assert k.lease(**base)["status"]=="approval_required"
    a=k.lease(**base,approval_token="approved")
    assert a["status"]=="leased"
    b=k.lease(**base,approval_token="approved")
    assert b["status"]=="lease_conflict"
    assert k.begin(a["task_id"],scope_hash="scope1",authorization_epoch="auth1")["status"]=="executing"
    r=k.settle(a["task_id"],status="settled",evidence_refs=["evidence/x.json"],outcome={"ok":True},scope_hash="scope1",authorization_epoch="auth1")
    assert r["status"]=="settled"
    assert k.lease(**base,approval_token="approved")["status"]=="converged_settled"

def test_scope_and_authorization_binding(tmp_path: Path):
    k=AutonomousKernel(tmp_path)
    a=k.lease(action="probe",target="127.0.0.1",risk="R1",basis=[],scope_hash="s",authorization_epoch="a",approval_token="x")
    assert k.begin(a["task_id"],scope_hash="wrong",authorization_epoch="a")["status"]=="stale_authority_context"

def test_final_closure(tmp_path: Path):
    r=build_final_closure(tmp_path)
    assert r["status"]=="final-closure"
    assert len(r["closed_gaps"]) >= 8
    assert (tmp_path/"evidence"/"final-engine-closure-v360.json").is_file()
    assert v360_test_matrix()["scenario_count"] >= 20
