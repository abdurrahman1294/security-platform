import json
from pathlib import Path
from modules.credential_intelligence_v19 import discover, verify_local_lab, discover_web_content


def test_discovery_recovers_exact_value(tmp_path):
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "backup.env").write_text("LAB_USER=alice\nLAB_PASSWORD=alice123\n")
    d = discover(tmp_path)
    assert d["count"] >= 1
    found = next(x for x in d["credentials"] if x["username"] == "alice")
    assert found["secret"] == "alice123"
    stored = json.loads((tmp_path / "evidence" / "credentials.json").read_text())
    assert any(x.get("secret") == "alice123" for x in stored)


def test_verification_blocked_off_loopback(tmp_path):
    assert verify_local_lab(tmp_path, "example.com") ["status"] == "blocked"


def test_web_probe_is_loopback_only(tmp_path):
    assert discover_web_content(tmp_path, "https://example.com")["status"] == "blocked"
