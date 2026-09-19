#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

from modules.engagement_runner_v33 import EngagementRunner
from modules.lab_certification_v33 import run_lab_cert
from modules.false_positive_engine_v33 import classify_finding, dedupe_findings


def test_lab_certification():
    data = run_lab_cert()
    assert data["failed"] == 0
    assert data["certified"] is True


def test_engagement_runner_resume(tmp_path: Path):
    r = EngagementRunner(tmp_path, "example.com", authorized=True, in_scope=True, dry_run=True)
    out1 = r.run(resume=False)
    assert out1["status"] == "ok"
    # mark one phase dirty then resume
    r.ledger["phases"]["report_draft"]["status"] = "error"
    r._save_ledger()
    out2 = r.run(resume=True)
    assert out2["status"] == "ok"
    assert r.ledger["phases"]["report_draft"]["status"] == "ok"


def test_fp_never_confirms():
    f = classify_finding({"info": {"name": "x", "severity": "critical"}, "matched-at": "https://a"})
    assert f["_state"] in {"observed", "suspected", "inconclusive"}
    assert f["_state"] != "confirmed"


def test_dedupe():
    items = [
        {"info": {"name": "A"}, "host": "h1"},
        {"info": {"name": "A"}, "host": "h1"},
        {"info": {"name": "B"}, "host": "h1"},
    ]
    assert len(dedupe_findings(items)) == 2
