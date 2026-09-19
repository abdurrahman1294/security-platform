import json
from pathlib import Path

from modules.deep_excellence_v226_v231 import (
    v226_exploitation, v227_validation_plan, v228_ad, v229_aws, v230_web_api, v231_quality,
)


def seed(root: Path):
    (root / "evidence").mkdir(parents=True, exist_ok=True)
    (root / "vulns").mkdir(parents=True, exist_ok=True)
    finding = {
        "template-id": "xss-test",
        "matched-at": "https://app.example.test/search?q=x",
        "surface": "web",
        "info": {"name": "Reflected XSS", "severity": "high", "tags": ["xss"]},
    }
    (root / "vulns" / "findings.json").write_text(json.dumps([finding]), encoding="utf-8")
    (root / "evidence" / "web-endpoints-v46.json").write_text(
        json.dumps({"endpoints": [{"endpoint": "https://app.example.test/search?q=x", "method_candidates": ["GET"], "parameters": ["q"]}]}),
        encoding="utf-8",
    )
    (root / "evidence" / "api-surface-v58.json").write_text(json.dumps({"endpoints": []}), encoding="utf-8")


def test_deep_excellence_builds_all_layers(tmp_path):
    seed(tmp_path)
    assert v226_exploitation(tmp_path).exists()
    assert v227_validation_plan(tmp_path).exists()
    assert v228_ad(tmp_path, target="app.example.test").exists()
    assert v229_aws(tmp_path, account_id="123456789012").exists()
    assert v230_web_api(tmp_path).exists()
    q = v231_quality(tmp_path, "app.example.test")
    data = json.loads(q.read_text())
    assert data["decision"] == "PASS"
    assert data["finding_count"] == 1


def test_deep_exploitation_marks_safe_adapter(tmp_path):
    seed(tmp_path)
    p = v226_exploitation(tmp_path)
    data = json.loads(p.read_text())
    row = data["rows"][0]
    assert row["kind"] == "reflected_xss"
    assert row["safe_adapter"] == "http-reflection-marker"
    assert row["proof_eligible"] is True
    assert row["proof_eligible"] is True


def test_ad_and_aws_are_plan_only_by_default(tmp_path):
    p1 = v228_ad(tmp_path, target="dc.example.test")
    p2 = v229_aws(tmp_path, account_id="123456789012")
    d1 = json.loads(p1.read_text())
    d2 = json.loads(p2.read_text())
    assert d1["executed"] is False
    assert d1["read_only"] is True
    assert d2["executed"] is False
    assert d2["mutations"] is False
    assert d2["secrets_retrieved"] is False
