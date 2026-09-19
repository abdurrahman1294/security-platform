import json
from modules.exploit_adapter_v33 import REGISTRY
from modules.exploit_policy_v34 import DEFAULT_POLICY, evaluate
from modules.exploit_planner_v35 import build_plan


def test_registry_has_only_safe_adapters():
    specs = REGISTRY.list()
    assert specs
    assert all(not s["destructive"] for s in specs)
    assert all(s["requires_operator_approval"] for s in specs)


def test_policy_rejects_unsafe_capabilities():
    assert DEFAULT_POLICY.validate() is True
    class Unsafe:
        destructive = True
        lab_only = False
    result = evaluate(Unsafe(), {}, approved=True, scope_ok=True)
    assert result["allowed"] is False


def test_v35_plan_blocks_without_approval(tmp_path):
    (tmp_path/"evidence").mkdir(); (tmp_path/"reports").mkdir()
    (tmp_path/"evidence"/"normalized-findings.json").write_text(json.dumps([
        {"finding_id":"F-1","title":"Reflected XSS","severity":"high","surface":"web","endpoint":"http://127.0.0.1/?q=x","cep_kind":"reflected_xss"}
    ]))
    p = build_plan(tmp_path, approved=False)
    rows=json.loads(p.read_text())
    assert rows[0]["adapter"] == "http-reflection-marker"
    assert rows[0]["decision"] == "BLOCKED"


def test_v36_additional_adapters_are_safe():
    import modules.exploit_adapters_v36
    specs = {s["adapter_id"]: s for s in REGISTRY.list()}
    assert "http-sqli-boolean-differential" in specs
    assert "lab-ssrf-local-canary" in specs
    assert not specs["http-sqli-boolean-differential"]["destructive"]
    assert specs["lab-ssrf-local-canary"]["lab_only"]


def test_v37_guard_scope_and_budget():
    from modules.proof_execution_guard_v37 import ExecutionGuard
    g = ExecutionGuard(["127.0.0.1"], max_requests=1)
    import pytest
    with pytest.raises(PermissionError):
        g.request("http://example.com/")
    with pytest.raises(RuntimeError):
        g.request("http://127.0.0.1:1/")
        g.request("http://127.0.0.1:1/")


def test_v38_analytics(tmp_path):
    from modules.proof_analytics_v38 import build
    (tmp_path/"evidence").mkdir(); (tmp_path/"reports").mkdir()
    (tmp_path/"evidence"/"proof-execution-ledger.json").write_text(json.dumps([
        {"adapter_id":"http-reflection-marker","result":"confirmed"},
        {"adapter_id":"http-sqli-boolean-differential","result":"inconclusive"},
    ]))
    p=build(tmp_path); data=json.loads(p.read_text())
    assert data["executions"] == 2
    assert data["results"]["confirmed"] == 1
