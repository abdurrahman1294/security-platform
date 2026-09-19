from pathlib import Path

import modules.universal_assessment_runner_v321 as v321


def _scope(tmp_path: Path) -> Path:
    p = tmp_path / "scope.txt"
    p.write_text("127.0.0.1\nlocalhost\nexample.test\n", encoding="utf-8")
    return p


def test_version():
    assert v321.VERSION == "3.21.0"


def test_plan_only_never_executes(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(v321, "run_tool", lambda *a, **k: called.append((a, k)))
    out = v321.execute_universal_assessment(tmp_path, target="127.0.0.1", scope_file=_scope(tmp_path), authorized=True, execute=False, surfaces=["internet_services"])
    assert out["status"] == "plan-only"
    assert called == []


def test_unauthorized_blocks_execution(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(v321, "run_tool", lambda *a, **k: called.append((a, k)))
    out = v321.execute_universal_assessment(tmp_path, target="127.0.0.1", scope_file=_scope(tmp_path), authorized=False, execute=True, surfaces=["internet_services"])
    assert out["status"] == "plan-only"
    assert called == []


def test_out_of_scope_blocks(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(v321, "run_tool", lambda *a, **k: called.append((a, k)))
    out = v321.execute_universal_assessment(tmp_path, target="192.0.2.44", scope_file=_scope(tmp_path), authorized=True, execute=True, surfaces=["internet_services"])
    assert out["status"] == "blocked"
    assert called == []


def test_registered_adapter_executes(tmp_path, monkeypatch):
    class Proc:
        returncode = 0
        stdout = "ok"
        stderr = ""
    calls = []
    monkeypatch.setattr(v321, "run_tool", lambda root, tool, argv, timeout: calls.append((tool, argv, timeout)) or Proc())
    out = v321.execute_universal_assessment(tmp_path, target="127.0.0.1", scope_file=_scope(tmp_path), authorized=True, execute=True, surfaces=["internet_services"])
    assert out["status"] == "completed"
    assert out["coverage"]["executed"] == 1
    assert calls[0][0] == "nmap"
    assert calls[0][1][0] == "nmap"


def test_specialist_surfaces_are_accounted_for(tmp_path, monkeypatch):
    monkeypatch.setattr(v321, "run_tool", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not run")))
    out = v321.execute_universal_assessment(tmp_path, target="127.0.0.1", scope_file=_scope(tmp_path), authorized=True, execute=True, surfaces=["firmware"])
    assert out["coverage"]["specialist_required"] == 1
    assert out["steps"][0]["status"] == "specialist-required"


def test_cellular_is_a_vantage_not_a_bypass(tmp_path, monkeypatch):
    class Proc:
        returncode = 0
        stdout = "ok"
        stderr = ""
    calls = []
    monkeypatch.setattr(v321, "run_tool", lambda root, tool, argv, timeout: calls.append((tool, argv)) or Proc())
    out = v321.execute_universal_assessment(tmp_path, target="127.0.0.1", scope_file=_scope(tmp_path), perspective="cellular_ipv6", authorized=True, execute=True, surfaces=["cellular_telecom"])
    assert out["perspective"] == "cellular_ipv6"
    assert out["safety"]["carrier_bypass"] is False
    assert len(calls) == 2


def test_tool_unavailable_is_blocked_not_executed(tmp_path, monkeypatch):
    def unavailable(*a, **k):
        raise FileNotFoundError("Tool is not installed: nmap")
    monkeypatch.setattr(v321, "run_tool", unavailable)
    out = v321.execute_universal_assessment(tmp_path, target="127.0.0.1", scope_file=_scope(tmp_path), authorized=True, execute=True, surfaces=["internet_services"])
    assert out["status"] == "partial"
    assert out["coverage"]["executed"] == 0
    assert out["coverage"]["blocked"] == 1
