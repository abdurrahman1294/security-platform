from pathlib import Path
import json
from modules.hypothesis_dependency_engine_v377 import build_state, write_state


def test_role_object_story_creates_blocked_high_value_hypothesis(tmp_path):
    state = build_state(
        objective="Is this approach feasible, and what should I test first?",
        story="The API returns different data for two roles. Login works, but one endpoint behaves strangely when object IDs change.",
        evidence=[{"specialist":"web","phase":"probe","evidence_produced":True,"evidence_artifacts":["pentest-http-probe.json"]}],
        actions=[
            {"specialist":"identity","phase":"authenticated","status":"blocked"},
            {"specialist":"web","phase":"api","status":"skipped"},
            {"specialist":"web","phase":"probe","status":"completed","evidence_produced":True,"evidence_artifacts":["pentest-http-probe.json"]},
        ],
    )
    assert state["status"] == "blocked_pending_evidence"
    assert state["hypotheses"][0]["is_finding"] is False
    assert state["blocked_dependencies"]
    assert state["high_value_next_tests"][0]["hypothesis_id"] in {"access-control-object-id", "api-role-differential"}


def test_evidence_does_not_turn_hypothesis_into_finding(tmp_path):
    state = build_state(
        objective="test authorization",
        story="two roles see different data for object IDs",
        evidence=[{"phase":"authenticated","evidence_produced":True,"evidence_artifacts":["authenticated/result.json"]}],
        actions=[{"phase":"authenticated","status":"completed","evidence_produced":True,"evidence_artifacts":["authenticated/result.json"]}],
    )
    assert all(h["is_finding"] is False for h in state["hypotheses"])
    assert all(h["evidence_required_before_finding"] for h in state["hypotheses"])


def test_state_is_persistable(tmp_path):
    state = build_state(objective="odd API endpoint", story="strange parser behavior", evidence=[], actions=[])
    write_state(tmp_path, state)
    loaded = json.loads((tmp_path / "evidence" / "hypothesis-dependency-v377.json").read_text())
    assert loaded["schema_version"] == "3.77.0"
