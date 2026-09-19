from pathlib import Path

from modules.scope import is_valid_target_format
from modules.security import in_scope
from modules.bug_bounty_program_v238 import build as build_policy


def test_target_validation_supports_urls_ipv6_and_internal_hosts():
    assert is_valid_target_format("https://example.com/app")
    assert is_valid_target_format("https://[2001:db8::10]:8443/")
    assert is_valid_target_format("dc01")
    assert not is_valid_target_format("https://user:pass@example.com/")
    assert not is_valid_target_format("https://example.com/#fragment")


def test_scope_normalization_handles_urls_ipv6_and_wildcards():
    assert in_scope("https://app.example.com/login", ["*.example.com"])
    assert in_scope("https://[2001:db8::10]:443/", ["2001:db8::/64"])
    assert not in_scope("https://evil-example.com/", ["*.example.com"])


def test_bounty_policy_normalizes_testing_rules(tmp_path: Path):
    policy_file = tmp_path / "program.json"
    policy_file.write_text(
        '{"program":"demo","scope":["example.com"],'
        '"allowed_testing":"web","forbidden":"destructive actions"}',
        encoding="utf-8",
    )
    out = build_policy(tmp_path / "out", policy_file=str(policy_file))
    assert out["policy_loaded"] is True
    assert out["rules"]["allowed_testing"] == ["web"]
    assert out["rules"]["forbidden"] == ["destructive actions"]


def test_bounty_execute_delegates_only_after_policy_and_authorization(tmp_path, monkeypatch):
    policy_file = tmp_path / "program.json"
    policy_file.write_text(
        '{"program":"demo","scope":["example.com"],"allowed_testing":["web","api"]}',
        encoding="utf-8",
    )
    from security_platform.core.engagement import Engagement
    import security_platform.engines.bounty as bounty_mod

    class FakePentest:
        def __init__(self, engagement, policy):
            assert policy.contains("example.com")
        def run(self, phases, require_authorization=True):
            assert require_authorization is False
            assert "web" in phases and "api" in phases
            return {"status": "completed"}

    monkeypatch.setattr(bounty_mod, "require_authorization", lambda: None, raising=False)
    monkeypatch.setattr("modules.security.require_authorization", lambda: None)
    monkeypatch.setattr("security_platform.engines.pentest.PentestEngine", FakePentest)
    e = Engagement("demo", "example.com", tmp_path / "out", tmp_path / "scope.txt")
    e.scope_file.write_text("example.com\n", encoding="utf-8")
    result = bounty_mod.BugBountyEngine(e).intelligence(policy_file=str(policy_file), execute=True)
    assert result["execution"]["started"] is True
    assert result["execution"]["delegated_pentest"]["phases"]
