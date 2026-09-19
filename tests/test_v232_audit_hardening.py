import json
import os
from pathlib import Path


def test_tool_boundary_rejects_dangerous_flags_and_paths(tmp_path):
    from modules.tool_adapter_hardening_v162 import validate_argv
    assert validate_argv("nmap", ["nmap", "-sV", "example.test"], root=tmp_path)[0]
    assert not validate_argv("nmap", ["nmap", "--script", "anything", "example.test"], root=tmp_path)[0]
    assert not validate_argv("nmap", ["nmap", "-oN", "/tmp/out.txt", "example.test"], root=tmp_path)[0]
    assert not validate_argv("nuclei", ["nuclei", "-t", "workflows/evil.yaml", "-u", "https://example.test"], root=tmp_path)[0]


def test_environment_is_allowlist_not_denylist(monkeypatch):
    from modules.tool_adapter_hardening_v162 import sanitized_environment
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "secret")
    monkeypatch.setenv("PENTEST_AUTH_COOKIE", "secret")
    monkeypatch.setenv("UNRELATED_SECRET", "secret")
    env = sanitized_environment("nmap")
    assert "AWS_ACCESS_KEY_ID" not in env
    assert "PENTEST_AUTH_COOKIE" not in env
    assert "UNRELATED_SECRET" not in env
    assert env.get("PATH") == os.defpath


def test_ad_execution_uses_temporary_credential_files(tmp_path, monkeypatch):
    import modules.deep_excellence_v226_v231 as deep
    scope = tmp_path / "scope.txt"
    scope.write_text("dc.example.test\n", encoding="utf-8")
    (tmp_path / "evidence").mkdir()
    monkeypatch.setenv("NXC_USER", "alice")
    monkeypatch.setenv("NXC_PASSWORD", "SuperSecret!")
    seen = []

    class FakeProc:
        returncode = 0
        stdout = "SMB output\n"
        stderr = ""

    class FakeTM:
        def __init__(self, root): pass
        def run(self, tool, argv, timeout=None):
            seen.append(list(argv))
            return FakeProc()

    monkeypatch.setattr(deep, "ToolManager", FakeTM)
    p = deep.v228_ad(tmp_path, target="dc.example.test", scope_file=str(scope), approved=True, execute=True)
    assert p.exists()
    assert seen
    joined = " ".join(seen[0])
    assert "SuperSecret!" not in joined
    assert "alice" not in joined
    assert all(not x.name.startswith("nxc-") for x in (tmp_path / "evidence").iterdir() if x.is_file())


def test_aws_inventory_stops_on_account_mismatch(tmp_path, monkeypatch):
    import modules.deep_excellence_v226_v231 as deep
    monkeypatch.setenv("AWS_ALLOWED_ACCOUNT_IDS", "123456789012")
    calls = []
    def fake(args, timeout=60, root=None):
        calls.append(args)
        if args == ("sts", "get-caller-identity"):
            return {"status": "completed", "output": json.dumps({"Account": "999999999999"}), "output_sha256": "x", "stderr": ""}
        return {"status": "completed", "output": "{}", "output_sha256": "y", "stderr": ""}
    monkeypatch.setattr(deep, "_run_aws", fake)
    p = deep.v229_aws(tmp_path, account_id="123456789012", approved=True, execute=True)
    data = json.loads(p.read_text())
    assert len(calls) == 1
    assert any(r.get("id") == "inventory-blocked" for r in data["results"])


def test_post_access_plan_is_non_executing(tmp_path):
    from modules.post_exploit import generate_post_exploit_guide
    p = generate_post_exploit_guide("shell", str(tmp_path), "linux")
    assert Path(p).exists()
    data = json.loads((tmp_path / "post-access-assessment.json").read_text())
    assert "credential collection" in data["forbidden_automation"]


def test_new_dynamic_policy_modules_use_context(tmp_path):
    from modules.platform_observability_v171 import build as obs
    from modules.finding_confidence_v181 import build as conf
    from modules.compliance_mapping_v183 import build as comp
    (tmp_path / "evidence").mkdir()
    (tmp_path / "vulns").mkdir()
    (tmp_path / "vulns" / "findings.json").write_text(json.dumps([{
        "template-id": "xss-1", "matched-at": "https://a.example.test/?q=x",
        "info": {"name": "Reflected XSS", "severity": "high", "description": "x", "tags": ["xss"]}
    }]), encoding="utf-8")
    o = obs(tmp_path); c = conf(tmp_path); m = comp(tmp_path)
    assert o["metrics"]["finding_count"] == 1
    assert c["finding_count"] == 1
    assert m["finding_count"] == 1


def test_exploitation_registry_and_policy_engine(tmp_path):
    import modules.exploit_adapters_v33 as adapters
    from modules.exploit_adapter_v33 import REGISTRY
    from modules.exploiter import InteractiveExploiter
    from modules.policy_engine_v232 import context
    assert adapters is not None
    assert REGISTRY.get("http-reflection-marker") is not None
    ex = InteractiveExploiter(str(tmp_path / "missing.json"), str(tmp_path / "out"))
    assert ex.load_findings() == []
    ctx = context(tmp_path)
    assert ctx["artifact_count"] >= 0
