import json
from pathlib import Path

from modules.governed_mission_fabric_v313 import (
    VERSION,
    build_workflow_coverage,
    build_governed_execution_plan,
    request_approvals,
    execute_approved,
)


def test_version():
    assert VERSION == "3.13.0"


def test_coverage_artifact(tmp_path):
    out = build_workflow_coverage(tmp_path)
    assert out["schema_version"] == VERSION
    assert (tmp_path / "evidence" / "workflow-coverage-v313.json").exists()
    assert "payload_generation_and_c2" in out["coverage"]


def test_coverage_marks_destructive_denied(tmp_path):
    out = build_workflow_coverage(tmp_path)
    assert out["coverage"]["destructive_actions"]["status"] == "denied"


def test_plan_is_bounded(tmp_path):
    out = build_governed_execution_plan(tmp_path, "example.com", max_steps=3)
    assert 1 <= len(out["steps"]) <= 3
    assert all(x["requires_authorization"] for x in out["steps"])
    assert all(x["requires_scope_check"] for x in out["steps"])


def test_plan_rejects_unmapped_role_without_crashing(tmp_path):
    out = build_governed_execution_plan(tmp_path, "example.com", objective="general", max_steps=8)
    assert isinstance(out["steps"], list)


def test_requests_are_created_for_active_actions(tmp_path):
    out = request_approvals(tmp_path, "example.com", max_steps=5)
    assert out["requests"]
    assert all(x["status"] == "pending" for x in out["requests"])


def test_execute_requires_authorization(tmp_path):
    scope = tmp_path / "scope.txt"
    scope.write_text("example.com\n")
    out = execute_approved(tmp_path, "example.com", scope, authorization=False)
    assert out["status"] == "blocked"


def test_execute_requires_scope(tmp_path):
    scope = tmp_path / "scope.txt"
    scope.write_text("allowed.example\n")
    out = execute_approved(tmp_path, "example.com", scope, authorization=True)
    assert out["status"] == "blocked"


def test_execute_without_tokens_does_not_run_active_actions(tmp_path):
    scope = tmp_path / "scope.txt"
    scope.write_text("example.com\n")
    out = execute_approved(tmp_path, "example.com", scope, authorization=True, max_steps=2)
    assert out["status"] == "completed"
    assert any(x["status"] == "approval_required" for x in out["results"] if x["action"] in {"subdomain_enum", "http_probe", "port_scan", "web_crawl", "vuln_candidate_scan", "service_enum", "ad_read_enum", "cloud_read_inventory"})


def test_request_artifact_is_json(tmp_path):
    request_approvals(tmp_path, "example.com", max_steps=3)
    data = json.loads((tmp_path / "evidence" / "governed-approval-requests-v313.json").read_text())
    assert data["schema_version"] == VERSION
