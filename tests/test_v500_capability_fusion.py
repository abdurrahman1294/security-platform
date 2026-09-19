from modules.ai_capability_fusion_v500 import FusionEngine, MCPBridge, TOOL_CATALOG

def test_large_catalog_is_metadata_only_until_adapter_registered(tmp_path):
    e = FusionEngine(tmp_path)
    assert len(TOOL_CATALOG) >= 100
    assert e.registry.available() == []
    assert all(x["status"] == "catalog-only" for x in e.registry.catalog())

def test_authorization_blocks_planning(tmp_path):
    e = FusionEngine(tmp_path)
    out = e.plan("127.0.0.1", "web assessment", authorized=False)
    assert out["status"] == "blocked"
    assert out["tasks"] == []

def test_planner_creates_durable_tasks_when_authorized(tmp_path):
    e = FusionEngine(tmp_path)
    e.registry.register("nmap", lambda **kw: {"evidence": ["ports.json"]})
    out = e.plan("127.0.0.1", "network service assessment", authorized=True)
    assert out["status"] == "planned"
    assert out["tasks"]
    assert e.store.snapshot()["tasks"]

def test_execution_requires_scope_and_authorization(tmp_path):
    e = FusionEngine(tmp_path)
    e.registry.register("nmap", lambda **kw: {"evidence": ["ports.json"]})
    plan = e.plan("127.0.0.1", "network", authorized=True)
    task_id = plan["tasks"][0]["task_id"]
    denied = e.execute_registered(task_id, "nmap", target="127.0.0.1",
                                  authorized=False, in_scope=lambda x: True)
    assert denied["reason"] == "authorization-required"

def test_mcp_bridge_is_planning_only(tmp_path):
    e = FusionEngine(tmp_path)
    bridge = MCPBridge(e)
    tools = bridge.handle({"jsonrpc":"2.0","id":1,"method":"tools/list"})
    names = [x["name"] for x in tools["result"]["tools"]]
    assert "security.plan" in names
    bad = bridge.handle({"jsonrpc":"2.0","id":2,"method":"tools/call",
                         "params":{"name":"shell","arguments":{}}})
    assert "error" in bad

def test_provider_routing_never_exposes_secret_values(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "SECRET")
    e = FusionEngine(tmp_path)
    routes = e.model_routes()
    assert routes["openai"]["configured"] is True
    assert "SECRET" not in str(routes)
