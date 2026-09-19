from modules.ai_offensive_agent_v363 import validate_plan, build_context


def test_ai_can_reason_aggressively_but_only_registered_tools_enter_plan():
    raw = {"actions": [
        {"tool": "nmap", "target": "127.0.0.1", "args": ["-sV"], "objective": "map service behavior"},
        {"tool": "arbitrary-shell", "target": "127.0.0.1", "args": ["id"], "objective": "execute command"},
    ]}
    out = validate_plan(raw, allowed_tools={"nmap"}, in_scope=lambda x: x == "127.0.0.1", authorized=True)
    assert len(out["accepted"]) == 1
    assert out["rejected"][0]["reason"] == "unregistered-tool"


def test_high_risk_requires_explicit_approval_token():
    raw = {"actions": [{"tool":"nuclei","target":"127.0.0.1","args":[],"risk":"high","objective":"validate hypothesis"}]}
    denied = validate_plan(raw, allowed_tools={"nuclei"}, in_scope=lambda x: True, authorized=True)
    assert denied["accepted"] == []
    assert denied["rejected"][0]["reason"] == "approval-required"
    approved = validate_plan(raw, allowed_tools={"nuclei"}, in_scope=lambda x: True, authorized=True, approval_token="lab-approval")
    assert len(approved["accepted"]) == 1


def test_scope_and_authorization_are_independent_gates():
    raw = {"actions": [{"tool":"nmap","target":"10.0.0.9","args":[],"objective":"probe"}]}
    a = validate_plan(raw, allowed_tools={"nmap"}, in_scope=lambda x: False, authorized=True)
    assert a["rejected"][0]["reason"] == "out-of-scope"
    b = validate_plan(raw, allowed_tools={"nmap"}, in_scope=lambda x: True, authorized=False)
    assert b["rejected"][0]["reason"] == "authorization-required"


def test_context_redacts_secrets_without_removing_attack_structure():
    c = build_context(target="127.0.0.1", objective="test", findings=[{"type":"jwt","token":"SECRET"}])
    assert "SECRET" not in str(c)
    assert "jwt" in str(c)
