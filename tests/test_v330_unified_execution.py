import json
from pathlib import Path
from modules.unified_assessment_execution_fabric_v330 import build_v330_fabric, v330_test_matrix


def hyp():
    return [{"id":"h1","chain":["a","b","c"],"priority":.8}]


def test_canonical_state_and_artifact(tmp_path):
    out=build_v330_fabric(tmp_path,target="127.0.0.1",assets=[{"id":"pc"}],evidence=[{"id":"e1","claim":"open","source":"nmap","trust":"instrument"}],hypotheses=hyp(),perspectives=["testbed"],timeline=[{"timestamp":"10","state":"new"},{"timestamp":"2","state":"old"}])
    assert out["schema_version"]=="3.30.0"
    assert out["canonical_state"]["timeline"][0]["timestamp"]=="2"
    assert Path(tmp_path,"evidence/unified-assessment-v330.json").exists()
    assert "password" not in json.dumps(out).lower()


def test_governance_blocks_execution():
    out=build_v330_fabric("/tmp/v330-test",target="127.0.0.1",hypotheses=hyp(),perspectives=["testbed"],authorized=True,execute=True,authorization_current=False)
    assert out["status"]=="blocked"
    assert "authorization-not-current" in out["readiness"]["blockers"]


def test_scope_and_target_lock():
    out=build_v330_fabric("/tmp/v330-test",target="x",hypotheses=hyp(),perspectives=["testbed"],execute=True,authorized=True,scope_locked=False)
    assert "scope-not-locked" in out["readiness"]["blockers"]


def test_failure_replan_is_first_class(tmp_path):
    out=build_v330_fabric(tmp_path,target="127.0.0.1",hypotheses=hyp(),perspectives=["testbed"],failures=[{"action":"validate","reason":"timeout","category":"transient"}])
    assert out["failure_replan"] and out["failure_replan"][0]["strategy"]=="retry"


def test_retest_plan(tmp_path):
    out=build_v330_fabric(tmp_path,target="127.0.0.1",remediation=[{"finding_id":"f1"}])
    assert out["retest_plan"][0]["action"]=="retest"


def test_invalid_perspective_and_denied_execution(tmp_path):
    out=build_v330_fabric(tmp_path,target="x",hypotheses=hyp(),perspectives=["bogus"],execute=True,authorized=False)
    assert out["status"]=="blocked"
    assert "invalid-perspective" in out["readiness"]["blockers"]
    assert "execution-without-authorization" in out["readiness"]["blockers"]


def test_matrix():
    m=v330_test_matrix(); assert m["schema_version"]=="3.30.0"; assert m["scenario_count"]>=35
