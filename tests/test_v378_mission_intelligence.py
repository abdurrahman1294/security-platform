import json
from pathlib import Path
from modules.mission_intelligence_fabric_v378 import mission_state


def test_v378_keeps_hypothesis_separate_from_finding(tmp_path):
    hs = {
        "status": "blocked_pending_evidence",
        "hypotheses": [{"id": "h1", "status": "blocked-pending-evidence", "class": "access-control", "priority": 1.0}],
        "high_value_next_tests": [{"hypothesis_id": "h1", "priority": 1.0, "next_test": "compare roles", "required_phase": "authenticated", "actionability": "blocked", "dependency": {"id": "authenticated-session", "reason": "approval required"}}],
        "blocked_dependencies": [{"hypothesis_id": "h1", "priority": 1.0, "dependency": {"id": "authenticated-session", "reason": "approval required"}}],
    }
    s = mission_state(root=tmp_path, client="c", target="127.0.0.1", scope="scope", objective="x", story="role object ids", hypothesis_state=hs, recent_actions=[])
    assert s["status"] == "blocked_pending_evidence"
    assert s["decision"]["finding_claims"] == "none without verified evidence"
    assert s["decision"]["scope_expansion"] is False


def test_v378_evidence_graph_is_not_corroboration(tmp_path):
    ev = tmp_path / "evidence"; ev.mkdir()
    (ev / "web-proof.json").write_text('{"ok":true}')
    (ev / "identity-proof.json").write_text('{"ok":true}')
    hs = {"hypotheses": [], "high_value_next_tests": [], "blocked_dependencies": []}
    s = mission_state(root=tmp_path, client="c", target="t", scope="s", objective="o", story="story", hypothesis_state=hs, recent_actions=[])
    assert all(e["corroborates"] is False for e in s["evidence_graph"]["edges"])


def test_v378_exploitation_bridge_is_bounded(tmp_path):
    hs = {"hypotheses": [{"id":"h1","status":"evidence-gap","class":"access-control","priority":1}], "high_value_next_tests": [], "blocked_dependencies": []}
    s = mission_state(root=tmp_path, client="c", target="t", scope="s", objective="o", story="role object ids", hypothesis_state=hs, recent_actions=[])
    c = s["exploitation_bridge"]["candidates"][0]
    assert c["technique_class"] == "idor-access-control"
    assert c["requires_verified_evidence"] is True
    assert c["finding_claim"] is False
