#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

from modules.high_risk_controls_v32 import (
    CONFIRM_PHRASES,
    MASTER_PHRASE,
    HighRiskController,
)
from modules.high_risk_executor_v32 import supervised_run


def _roe(path: Path, actions: list[str]) -> Path:
    data = {
        "engagement": "lab",
        "written_authorization": True,
        "allow_high_risk_actions": actions,
    }
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_default_denied(tmp_path: Path):
    ctl = HighRiskController(tmp_path)
    ok, reason = ctl.is_allowed("password_spray", "x")
    assert not ok


def test_enable_requires_phrases_and_roe(tmp_path: Path):
    ctl = HighRiskController(tmp_path)
    roe = _roe(tmp_path / "roe.json", ["password_spray"])
    ctl.load_roe(roe)
    denied = ctl.enable_action(
        "password_spray",
        authorized=True,
        master_phrase="wrong",
        action_phrase=CONFIRM_PHRASES["password_spray"],
    )
    assert denied["status"] == "denied"
    enabled = ctl.enable_action(
        "password_spray",
        authorized=True,
        master_phrase=MASTER_PHRASE,
        action_phrase=CONFIRM_PHRASES["password_spray"],
    )
    assert enabled["status"] == "enabled"
    token = enabled["token"]
    ok, _ = ctl.is_allowed("password_spray", token)
    assert ok


def test_roe_must_allow(tmp_path: Path):
    ctl = HighRiskController(tmp_path)
    roe = _roe(tmp_path / "roe.json", [])  # none allowed
    ctl.load_roe(roe)
    out = ctl.enable_action(
        "rce_chain",
        authorized=True,
        master_phrase=MASTER_PHRASE,
        action_phrase=CONFIRM_PHRASES["rce_chain"],
    )
    assert out["status"] == "denied"
    assert out["reason"] == "roe_does_not_allow_action"


def test_kill_switch(tmp_path: Path):
    ctl = HighRiskController(tmp_path)
    roe = _roe(tmp_path / "roe.json", ["lateral_movement"])
    ctl.load_roe(roe)
    enabled = ctl.enable_action(
        "lateral_movement",
        authorized=True,
        master_phrase=MASTER_PHRASE,
        action_phrase=CONFIRM_PHRASES["lateral_movement"],
    )
    token = enabled["token"]
    ctl.engage_kill_switch()
    ok, reason = ctl.is_allowed("lateral_movement", token)
    assert not ok
    assert reason == "kill_switch_active"


def test_supervised_run_single_use(tmp_path: Path):
    ctl = HighRiskController(tmp_path)
    roe = _roe(tmp_path / "roe.json", ["exfiltration_simulation"])
    ctl.load_roe(roe)
    enabled = ctl.enable_action(
        "exfiltration_simulation",
        authorized=True,
        master_phrase=MASTER_PHRASE,
        action_phrase=CONFIRM_PHRASES["exfiltration_simulation"],
    )
    token = enabled["token"]
    out = supervised_run(tmp_path, "exfiltration_simulation", token=token, target="lab.local", controller=ctl)
    assert out["status"] == "supervised_plan_created"
    # single-use consumed
    ok, _ = ctl.is_allowed("exfiltration_simulation", token)
    assert not ok
