import json
from modules.exposure_validation_fabric_v314 import (
    VERSION, build_capability_delta, build_nonlinear_mission, record_clues,
    review_failure, validate_exposure, build_control_validation,
    build_remediation_retest, build_continuous_revalidation, build_v314_fabric,
)

def test_version():
    assert VERSION == "3.14.0"

def test_capability_delta(tmp_path):
    out = build_capability_delta(tmp_path)
    assert out["schema_version"] == VERSION
    assert "nonlinear_branch_search" in out["new_capabilities"]

def test_nonlinear_branches_are_bounded(tmp_path):
    out = build_nonlinear_mission(tmp_path, "example.com", max_branches=99)
    assert 1 <= len(out["branches"]) <= 8
    assert all(x["prerequisites"] for x in out["branches"])

def test_clue_graph_preserves_untrusted_observations(tmp_path):
    out = record_clues(tmp_path, [{"supports": ["x"], "value": "observed"}])
    assert out["clues"][0]["source_trust"] == "untrusted_until_correlated"

def test_failure_review_detects_scope():
    out = review_failure("authorization revoked", action="port_scan")
    assert out["category"] == "scope_or_authorization"
    assert not out["retry"]

def test_failure_review_allows_transient_retry():
    out = review_failure("connection timeout", action="http_probe")
    assert out["category"] == "transient"
    assert out["retry"]

def test_exposure_verdicts():
    assert validate_exposure({"reachable": True, "attack_path": True})["decision"] == "behaviorally_reachable"
    assert validate_exposure({"proof": True}, live_execution=True)["decision"] == "validated_exploitable"
    assert validate_exposure({"proof": True}, restricted=True)["decision"] == "restricted_unverified"
    assert validate_exposure({}, control_result="blocked")["decision"] == "control_blocked"

def test_control_validation_is_governed(tmp_path):
    out = build_control_validation(tmp_path, ["T1059"])
    assert out["scenarios"][0]["requires"]

def test_remediation_requires_retest_approval(tmp_path):
    out = build_remediation_retest(tmp_path, [{"finding_id": "f1", "decision": "validated_exploitable"}])
    assert out["items"][0]["retest"]["requires_new_approval"]

def test_continuous_revalidation_has_triggers(tmp_path):
    out = build_continuous_revalidation(tmp_path, {"assets": 1})
    assert "asset inventory delta" in out["triggers"]

def test_full_fabric(tmp_path):
    out = build_v314_fabric(tmp_path, "example.com", "general", [{"kind": "asset"}])
    assert set(out) == {"capability_delta", "nonlinear_mission", "clues", "control_validation", "remediation_retest", "continuous_revalidation"}
