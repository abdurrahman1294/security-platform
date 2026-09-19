#!/usr/bin/env python3
"""Tests for autonomy policy, prioritizer, approval queue, and loop."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from modules.approval_queue import ApprovalQueue
from modules.autonomy_policy import AutonomyPolicy, Decision, RiskClass
from modules.autonomous_loop import AutonomousLoop
from modules.task_prioritizer import prioritize, write_priority_queue


def test_default_deny_unknown_action():
    p = AutonomyPolicy(profile="assess")
    assert p.decide("not_a_real_action", authorized=True, in_scope=True) == Decision.DENY


def test_unauthorized_denied():
    p = AutonomyPolicy(profile="assess")
    assert p.decide("subdomain_enum", authorized=False, in_scope=True) == Decision.DENY


def test_out_of_scope_denied():
    p = AutonomyPolicy(profile="assess")
    assert p.decide("subdomain_enum", authorized=True, in_scope=False) == Decision.DENY


def test_recon_profile_allows_r1():
    p = AutonomyPolicy(profile="recon")
    assert p.risk_for("port_scan") == RiskClass.R1
    assert p.decide("port_scan", authorized=True, in_scope=True) == Decision.ALLOW_AUTO


def test_r3_needs_approval_without_token():
    p = AutonomyPolicy(profile="assisted")
    assert p.decide("controlled_validation", authorized=True, in_scope=True) == Decision.NEEDS_APPROVAL


def test_r3_allow_with_token():
    p = AutonomyPolicy(profile="assisted")
    assert (
        p.decide("controlled_validation", authorized=True, in_scope=True, approval_token="x")
        == Decision.ALLOW_AUTO
    )


def test_r4_always_denied():
    p = AutonomyPolicy(profile="assisted")
    assert p.decide("exploit_rce", authorized=True, in_scope=True, approval_token="x") == Decision.DENY
    assert p.decide("password_spray", authorized=True, in_scope=True) == Decision.DENY
    assert p.decide("lateral_movement", authorized=True, in_scope=True) == Decision.DENY


def test_kill_switch():
    p = AutonomyPolicy(profile="assess")
    p.kill_switch = True
    assert p.decide("http_probe", authorized=True, in_scope=True) == Decision.DENY


def test_approval_queue_flow(tmp_path: Path):
    q = ApprovalQueue(tmp_path)
    req = q.submit("controlled_validation", "https://a.example", "validate", risk="R3")
    assert req.request_id
    token = q.approve(req.request_id)
    assert token
    assert q.consume_token(req.request_id, token, "controlled_validation", "https://a.example")
    # single use
    assert not q.consume_token(req.request_id, token, "controlled_validation", "https://a.example")


def test_approval_bound_to_action_target(tmp_path: Path):
    q = ApprovalQueue(tmp_path)
    req = q.submit("controlled_validation", "https://a.example", "validate")
    token = q.approve(req.request_id)
    assert not q.consume_token(req.request_id, token, "controlled_validation", "https://OTHER")


def test_prioritizer_without_hosts(tmp_path: Path):
    tasks = prioritize(tmp_path, "example.com")
    actions = {t.action for t in tasks}
    assert "subdomain_enum" in actions
    assert "port_scan" in actions


def test_prioritizer_with_hosts(tmp_path: Path):
    recon = tmp_path / "recon"
    recon.mkdir()
    (recon / "live-hosts.txt").write_text("https://a.example.com\n", encoding="utf-8")
    tasks = prioritize(tmp_path, "example.com")
    actions = {t.action for t in tasks}
    assert "coverage_analysis" in actions
    path = write_priority_queue(tmp_path, "example.com")
    assert path.exists()
    data = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(data, list) and data


def test_loop_denies_without_auth(tmp_path: Path):
    loop = AutonomousLoop(tmp_path, "example.com", authorized=False, in_scope=True, dry_run=True)
    out = loop.run(cycles=1)
    # all actionable decisions should not execute
    assert out["tasks_run_total"] == 0


def test_loop_dry_run_with_auth_scope(tmp_path: Path):
    loop = AutonomousLoop(tmp_path, "example.com", authorized=True, in_scope=True, dry_run=True)
    out = loop.run(cycles=1)
    assert out["dry_run"] is True
    # should have attempted some auto tasks in dry-run
    assert out["tasks_run_total"] >= 1
    summary = tmp_path / "evidence" / "autonomous-summary.json"
    assert summary.exists()


def test_loop_queues_r3(tmp_path: Path):
    # create fake findings to trigger controlled_validation suggestions
    vulns = tmp_path / "vulns"
    vulns.mkdir()
    (vulns / "findings.json").write_text(
        json.dumps([{"info": {"name": "X", "severity": "high"}, "host": "https://a.example.com"}]),
        encoding="utf-8",
    )
    loop = AutonomousLoop(
        tmp_path,
        "example.com",
        policy=AutonomyPolicy(profile="assess"),
        authorized=True,
        in_scope=True,
        dry_run=True,
    )
    out = loop.run_once()
    statuses = [r.get("status") for r in out.get("results", [])]
    assert "queued_for_approval" in statuses
    assert any(r.get("action") == "controlled_validation" for r in out.get("results", []))


def test_budget_exhaustion(tmp_path: Path):
    policy = AutonomyPolicy(profile="assess")
    policy.budgets.max_tasks = 0
    loop = AutonomousLoop(tmp_path, "example.com", policy=policy, authorized=True, in_scope=True)
    out = loop.run_once()
    assert out["status"] == "budget_exhausted"
