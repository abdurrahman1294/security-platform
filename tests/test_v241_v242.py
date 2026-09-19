import json
from pathlib import Path
from modules.research_exhaustion_v241 import build as research
from modules.final_readiness_v242 import build as readiness
from modules.bug_bounty_program_v238 import build as bounty_policy


def test_research_exhaustion_is_bounded_and_scope_safe(tmp_path):
    ev = tmp_path / "evidence"
    ev.mkdir()
    (ev / "assets.json").write_text(json.dumps({"assets": [{"host": "example.com"}]}))
    (ev / "bug-bounty-plan-v239.json").write_text(json.dumps({"plan": [{"tests": ["a", "b"]}]}))
    out = research(tmp_path, "example.com", round_limit=100)
    assert out["round_limit"] == 32
    assert out["safety"]["scope_expansion"] is False
    assert out["safety"]["automatic_submission"] is False
    assert (ev / "research-exhaustion-v241.json").exists()


def test_final_readiness_reports_missing_artifacts(tmp_path):
    out = readiness(tmp_path, "example.com")
    assert out["decision"] == "NOT_READY"
    assert "engagement.json" in out["blockers"]


def test_bounty_policy_accepts_yaml(tmp_path):
    policy = tmp_path / "policy.yaml"
    policy.write_text("program: demo\nscope:\n  - app.example.com\n", encoding="utf-8")
    out = bounty_policy(tmp_path, policy_file=str(policy))
    assert out["policy_loaded"] is True
    assert "app.example.com" in out["rules"]["scope"]
