from pathlib import Path
from security_platform.core.handoff import publish, load
from security_platform.core.preflight import check
from security_platform.core.policy import ScopePolicy

def test_handoff_tamper_is_rejected(tmp_path):
    publish(tmp_path, "osint", {"assets": ["api.example.com"]})
    p=tmp_path/"evidence"/"handoff-osint.json"
    text=p.read_text()
    p.write_text(text.replace("api.example.com", "evil.example.com"))
    assert load(tmp_path, "osint") == {}

def test_preflight_fails_closed(tmp_path):
    pf=check("example.com", tmp_path/"missing.txt")
    assert not pf.ready_for_active
    assert "scope-file-missing" in pf.blockers

def test_preflight_accepts_exact_and_subdomain(tmp_path):
    scope=tmp_path/"scope.txt"; scope.write_text("example.com\n*.example.com\n")
    assert check("example.com", scope).ready_for_active
    assert check("api.example.com", scope).ready_for_active
    assert not check("evil-example.com", scope).ready_for_active

def test_scope_policy_uses_central_scope_semantics(tmp_path):
    scope=tmp_path/"scope.txt"; scope.write_text("10.10.10.0/24\n*.example.com\n")
    p=ScopePolicy.from_file(scope, "10.10.10.5")
    assert p.contains("10.10.10.8")
    assert p.contains("api.example.com")
    assert not p.contains("evil-example.com")


def test_passive_platform_run_does_not_require_scope(tmp_path):
    from security_platform.core.platform import SecurityPlatform
    from security_platform.core.engagement import Engagement
    out = SecurityPlatform(Engagement("Acme", "Example Research Subject", tmp_path)).run_selected(("osint",), public_osint=False)
    assert out["engines"][0]["engine"] == "osint"

def test_bounty_candidates_never_expand_program_scope(tmp_path):
    import json
    from modules.bug_bounty_program_v238 import build
    policy = tmp_path / "program.json"
    policy.write_text(json.dumps({"scope": ["example.com"]}), encoding="utf-8")
    out = build(tmp_path, policy_file=str(policy), targets=["evil.example.net"])
    assert out["rules"]["scope"] == ["example.com"]
    assert out["candidate_assets"] == ["evil.example.net"]

def test_bounty_execution_blocks_out_of_program_scope_before_authorization(tmp_path):
    import json
    from security_platform.core.engagement import Engagement
    from security_platform.engines.bounty import BugBountyEngine
    policy = tmp_path / "program.json"
    policy.write_text(json.dumps({"scope": ["example.com"]}), encoding="utf-8")
    result = BugBountyEngine(Engagement("Acme", "evil.example.net", tmp_path)).intelligence("Demo", str(policy), execute=True)
    assert result["execution"]["started"] is False
    assert result["execution"]["blocked_reason"] == "target-not-in-program-scope"

def test_handoff_schema_version_is_verified(tmp_path):
    import json
    from security_platform.core.handoff import publish, load
    publish(tmp_path, "osint", {"assets": ["api.example.com"]})
    p=tmp_path/"evidence"/"handoff-osint.json"
    data=json.loads(p.read_text())
    data["schema_version"]="0.0"
    p.write_text(json.dumps(data), encoding="utf-8")
    assert load(tmp_path, "osint") == {}

def test_nuclei_template_traversal_is_rejected(tmp_path):
    from modules.tool_adapter_hardening_v162 import validate_argv
    assert not validate_argv("nuclei", ["nuclei", "-t", "cves/../../evil.yaml", "-u", "https://example.com"], root=tmp_path)[0]

def test_nmap_port_spec_is_bounded(tmp_path):
    from modules.tool_adapter_hardening_v162 import validate_argv
    assert validate_argv("nmap", ["nmap", "-p", "80,443", "example.com"], root=tmp_path)[0]
    assert not validate_argv("nmap", ["nmap", "-p", "http", "example.com"], root=tmp_path)[0]

def test_aws_is_inside_shared_tool_boundary():
    from modules.tool_adapter_hardening_v162 import validate_argv
    assert validate_argv("aws", ["aws", "sts", "get-caller-identity", "--output", "json"])[0]
    assert not validate_argv("aws", ["aws", "iam", "delete-user", "--user-name", "x"])[0]
