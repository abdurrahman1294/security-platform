#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

from modules.adversarial_self_test_v30 import run_adversarial_tests
from modules.executable_capability_matrix import evaluate, write_report
from modules.red_team_support_v30 import generate_red_team_pack


def test_adversarial_suite_mostly_passes():
    data = run_adversarial_tests()
    # Allow at most 1 soft failure for API variance in adaptive module
    assert data["failed"] <= 1
    assert data["passed"] >= 9


def test_capability_matrix(tmp_path: Path):
    data = evaluate()
    assert data["summary"]["total"] >= 15
    path = write_report(tmp_path)
    assert path.exists()


def test_red_team_pack(tmp_path: Path):
    out = generate_red_team_pack(tmp_path, domain="corp.local", dc_ip="10.10.10.10", target="corp.local")
    assert out["status"] == "ok"
    assert len(out["files"]) >= 4
    for f in out["files"]:
        assert Path(f).exists()
