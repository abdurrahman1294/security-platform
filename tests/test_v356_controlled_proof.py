import json
from pathlib import Path
import pytest
from modules.controlled_proof_fabric_v356 import request_proof, approve_proof, execute_approved_proof, catalog, v356_test_matrix
from modules.exploit_adapter_v33 import REGISTRY
import modules.exploit_adapters_v33, modules.exploit_adapters_v36

def _fixture(tmp_path):
    (tmp_path/"evidence").mkdir()
    (tmp_path/"vulns").mkdir()
    finding={"finding_id":"F1","cep_kind":"reflected_xss","surface":"web",
             "endpoint":"http://127.0.0.1:8765/?q=x"}
    (tmp_path/"vulns"/"findings.json").write_text(json.dumps([finding])); (tmp_path/"evidence"/"normalized-findings.json").write_text(json.dumps([finding]))
    scope=tmp_path/"scope.txt"; scope.write_text("127.0.0.1\n")
    return finding, scope

def test_request_approve_execute_requires_single_use_token(tmp_path, monkeypatch):
    finding, scope=_fixture(tmp_path)
    req=request_proof(tmp_path,finding,"http-reflection-marker","verify fixture")
    assert req["status"]=="pending"
    token=approve_proof(tmp_path,req["request_id"])["token"]
    # no network: guard will make the request and fail safely, but ledger should not be created
    monkeypatch.setattr("modules.proof_execution_guard_v37.ExecutionGuard.request",
                        lambda self, url, method="GET", headers=None, timeout=8: {"ok":False,"status":599,"headers":{},"body":"","final_url":url,"error":"fixture unavailable"})
    out=execute_approved_proof(tmp_path,"F1",str(scope),req["request_id"],token)
    assert out["approved"] is True
    with pytest.raises(PermissionError):
        execute_approved_proof(tmp_path,"F1",str(scope),req["request_id"],token)

def test_catalog_is_governed():
    c=catalog()
    assert c["governance"]["single_use_tokens"]
    assert not c["governance"]["arbitrary_commands"]
    assert all(not a["destructive"] for a in c["adapters"])
    assert v356_test_matrix()["scenario_count"] >= 30

def test_adapters_require_guard():
    f={"cep_kind":"reflected_xss","surface":"web","endpoint":"http://127.0.0.1/?q=x"}
    h=REGISTRY.handler("http-reflection-marker")
    assert h(f)["result"]=="blocked"
    h=REGISTRY.handler("http-open-redirect")
    assert h({"cep_kind":"open_redirect","surface":"web","endpoint":"http://127.0.0.1/?u=x"})["result"]=="blocked"
