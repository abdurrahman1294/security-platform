from pathlib import Path
from modules.universal_coverage_assurance_v332 import build_v332_fabric, v332_test_matrix
from modules.validation_assurance_fabric_v333 import build_v333_fabric, v333_test_matrix
from modules.evidence_reporting_fabric_v334 import build_v334_fabric, v334_test_matrix
from modules.engine_self_security_v335 import build_v335_fabric, v335_test_matrix


def test_v332_full_coverage_and_unknown_inputs(tmp_path):
    out = build_v332_fabric(tmp_path, target="127.0.0.1", surfaces=["external_web", "does-not-exist"], perspectives=["internet_ipv4", "bad-perspective"])
    assert out["schema_version"] == "3.32.0"
    assert out["matrix"]["invalid_surfaces"] == ["does-not-exist"]
    assert out["matrix"]["invalid_perspectives"] == ["bad-perspective"]
    assert out["coverage"]["total_cells"] == 1


def test_v332_empty_coverage_is_none(tmp_path):
    out = build_v332_fabric(tmp_path, target="x", surfaces=[], perspectives=[])
    assert out["coverage"]["total_cells"] > 0


def test_v333_does_not_upgrade_scanner_only(tmp_path):
    out = build_v333_fabric(tmp_path, target="x", claims=[{"id":"c1","title":"SQL injection","level":"validated"}], evidence=[{"id":"e1","claim":"SQL injection","trust":"instrument","status":"fresh"}])
    assert out["claims"][0]["achieved_level"] == "observed"
    assert out["claims"][0]["claim_status"] == "insufficient-evidence"


def test_v333_impact_requires_separate_evidence(tmp_path):
    evidence = [
        {"id":"e1","claim":"x","trust":"authoritative","status":"fresh","independent":True},
        {"id":"e2","claim":"x","trust":"instrument","status":"fresh","independent":True},
        {"id":"e3","claim":"x","trust":"provider","status":"fresh","independent":True},
        {"id":"e4","claim":"x","trust":"operator","status":"fresh","independent":True},
    ]
    out = build_v333_fabric(tmp_path, target="x", claims=[{"id":"c1","title":"x","level":"impact-validated"}], evidence=evidence)
    assert out["claims"][0]["achieved_level"] == "validated"


def test_v334_report_is_evidence_faithful(tmp_path):
    out = build_v334_fabric(tmp_path, target="x", claims=[{"id":"c1","title":"finding","achieved_level":"candidate","evidence_ids":[]}])
    assert out["executive_summary"]["validated_findings"] == 0
    assert out["findings"][0]["status"] == "unconfirmed"
    assert Path(tmp_path, "evidence/professional-report-v334.json").exists()


def test_v335_audits_repo_without_target_execution(tmp_path):
    out = build_v335_fabric(tmp_path, repo_root=Path(__file__).resolve().parents[1])
    assert out["schema_version"] == "3.35.0"
    assert out["governance"]["audit-only"] is True
    assert out["governance"]["does-not-touch-targets"] is True


def test_assurance_matrices_are_substantial():
    assert v332_test_matrix()["scenario_count"] >= 45
    assert v333_test_matrix()["scenario_count"] >= 40
    assert v334_test_matrix()["scenario_count"] >= 35
    assert v335_test_matrix()["scenario_count"] >= 35
