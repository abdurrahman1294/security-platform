import json
from pathlib import Path
from modules.adversary_simulation_planner_v329 import (
    build_v329_fabric, build_micro_chain_candidates, v329_test_matrix,
)


def sample_chain():
    return [{
        "chain_id": "chain-a", "chain": ["cellular", "ip", "router", "service", "account"],
        "priority": .8, "weak_link_score": .6, "evidence_ids": ["obs-1"],
    }]


def test_builds_unified_fabric_and_artifact(tmp_path):
    out = build_v329_fabric(
        tmp_path, target="203.0.113.10", assets=[{"id": "a", "type": "computer", "label": "pc"}],
        observations=[{"id": "obs-1", "claim": "service reachable", "source": "nmap", "trust": "instrument"}],
        chains=sample_chain(), perspective="internet_ipv4", perspectives=["cellular_ipv4", "cellular_ipv6"],
    )
    assert out["schema_version"] == "3.29.0"
    assert out["status"] == "ready"
    assert out["governance"]["execute_requested"] is False
    assert Path(tmp_path, "evidence/adversary-simulation-v329.json").exists()
    assert "password" not in json.dumps(out).lower()


def test_authorized_execution_request_is_still_planning_only_delegated(tmp_path):
    out = build_v329_fabric(tmp_path, target="127.0.0.1", assets=[], chains=sample_chain(),
                            authorized=True, execute=True, authorization_current=True,
                            perspective="testbed")
    assert out["readiness"]["ready"] is True
    assert all(s["execution"] == "delegated-only" for s in out["validation_plan"])


def test_scope_or_authorization_revocation_blocks(tmp_path):
    out = build_v329_fabric(tmp_path, target="127.0.0.1", assets=[], chains=sample_chain(),
                            authorized=True, execute=True, scope_locked=False,
                            authorization_current=False, perspective="testbed")
    assert out["status"] == "blocked"
    assert "scope-not-locked" in out["readiness"]["blockers"]
    assert "authorization-not-current" in out["readiness"]["blockers"]


def test_micro_chain_is_not_compromise():
    hs = [{"id": "h", "chain": ["a", "b", "c", "d"], "weak_link": .5}]
    out = build_micro_chain_candidates(hs)
    assert out and out[0]["status"] == "needs-evidence"
    assert "compromise" not in out[0]["status"]


def test_invalid_perspective_is_reported(tmp_path):
    out = build_v329_fabric(tmp_path, target="x", assets=[], chains=[], perspective="bogus")
    assert out["status"] == "blocked"
    assert "invalid-perspective" in out["readiness"]["blockers"]


def test_matrix_is_bounded():
    m = v329_test_matrix()
    assert m["schema_version"] == "3.29.0"
    assert m["scenario_count"] >= 25
    assert "never_infer_authorization" in m["invariants"]
