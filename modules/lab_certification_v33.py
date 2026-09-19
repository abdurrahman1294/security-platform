#!/usr/bin/env python3
"""Lab certification suite: verifies control-plane guarantees on a disposable workspace."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from modules.autonomy_policy import AutonomyPolicy, Decision
from modules.engagement_runner_v33 import EngagementRunner
from modules.high_risk_controls_v32 import CONFIRM_PHRASES, MASTER_PHRASE, HighRiskController
from modules.scope import is_valid_target_format


def run_lab_cert() -> dict[str, Any]:
    results = []

    def check(name: str, ok: bool, detail: str = "ok"):
        results.append({"name": name, "passed": bool(ok), "detail": detail})

    # 1 scope format
    check("reject_shell_meta_target", not is_valid_target_format("a.com;id"))

    # 2 default deny high risk
    with tempfile.TemporaryDirectory() as td:
        ctl = HighRiskController(td)
        ok, _ = ctl.is_allowed("rce_chain", "x")
        check("high_risk_default_deny", not ok)

    # 3 autonomy deny without auth
    d = AutonomyPolicy().decide("subdomain_enum", authorized=False, in_scope=True)
    check("autonomy_unauth_deny", d == Decision.DENY)

    # 4 engagement runner blocked without gates
    with tempfile.TemporaryDirectory() as td:
        out = EngagementRunner(td, "example.com", authorized=False, in_scope=False).run()
        check("runner_requires_auth_scope", out.get("status") == "blocked")

    # 5 engagement runner dry success
    with tempfile.TemporaryDirectory() as td:
        out = EngagementRunner(td, "example.com", authorized=True, in_scope=True, dry_run=True).run()
        check("runner_dry_ok", out.get("status") == "ok", str(out.get("status")))
        check("ledger_exists", (Path(td) / "evidence" / "engagement-ledger.json").exists())
        check("cockpit_exists", (Path(td) / "evidence" / "operator-cockpit.json").exists())
        check("graph_exists", (Path(td) / "evidence" / "evidence-graph.json").exists())

    # 6 high-risk enable/kill
    with tempfile.TemporaryDirectory() as td:
        roe = Path(td) / "roe.json"
        roe.write_text(json.dumps({"allow_high_risk_actions": ["password_spray"]}), encoding="utf-8")
        ctl = HighRiskController(td)
        ctl.load_roe(roe)
        en = ctl.enable_action(
            "password_spray",
            authorized=True,
            master_phrase=MASTER_PHRASE,
            action_phrase=CONFIRM_PHRASES["password_spray"],
        )
        check("high_risk_enable", en.get("status") == "enabled")
        ctl.engage_kill_switch()
        ok, reason = ctl.is_allowed("password_spray", en.get("token"))
        check("kill_switch_blocks", (not ok) and reason == "kill_switch_active")

    # 7 no auto-confirm false positive engine
    from modules.false_positive_engine_v33 import classify_finding
    f = classify_finding({"info": {"name": "Critical RCE", "severity": "critical"}, "host": "a"})
    check("never_auto_confirm", f.get("_state") != "confirmed")

    passed = sum(1 for r in results if r["passed"])
    return {
        "passed": passed,
        "failed": len(results) - passed,
        "total": len(results),
        "results": results,
        "certified": passed == len(results),
    }
