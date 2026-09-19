import json
from pathlib import Path
from modules.superior_capability_fabric_v311 import (
    build_agentic_plan, import_sarif, correlate_source_runtime,
    import_browser_trace, build_continuous_assurance, build_benchmark_metrics,
)

def test_agentic_plan_has_roles_dependencies_and_resume_key(tmp_path):
    out = build_agentic_plan(tmp_path, "example.com", "full-assessment")
    assert out["schema_version"] == "3.11.0"
    assert len(out["roles"]) >= 8
    assert any(x["dependencies"] for x in out["tasks"])
    assert out["resume_key"]
    assert (tmp_path / "evidence" / "superior-agentic-plan-v311.json").exists()

def test_sarif_import_and_source_runtime_correlation(tmp_path):
    sarif = tmp_path / "results.sarif"
    sarif.write_text(json.dumps({"runs":[{"tool":{"driver":{"name":"Semgrep","rules":[{"id":"RULE-1","name":"unsafe sink"}]}},"results":[{"ruleId":"RULE-1","message":{"text":"dangerous sink in api.py"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"api.py"},"region":{"startLine":12}}}]}]}]}))
    out = import_sarif(tmp_path, sarif, "Semgrep")
    assert out["count"] == 1
    (tmp_path / "evidence" / "runtime.json").write_text(json.dumps({"requests":[{"path":"api.py"}]}))
    corr = correlate_source_runtime(tmp_path, runtime_artifact="runtime.json")
    assert corr["source_count"] == 1
    assert corr["correlations"][0]["runtime_correlated"] is True

def test_browser_trace_normalization(tmp_path):
    har = tmp_path / "trace.har"
    har.write_text(json.dumps({"log":{"entries":[{"request":{"method":"GET","url":"https://example.test/api"},"response":{"status":200,"content":{"mimeType":"application/json"}},"time":12.3}]}}))
    out = import_browser_trace(tmp_path, har)
    assert out["count"] == 1
    assert out["flows"][0]["status"] == 200
    assert out["no_credentials_retained"] is True

def test_continuous_assurance_and_benchmark(tmp_path):
    ev = tmp_path / "evidence"; ev.mkdir()
    (ev / "one.json").write_text('{"a":1}')
    first = build_continuous_assurance(tmp_path)
    (ev / "baseline.json").write_text(json.dumps(first))
    (ev / "one.json").write_text('{"a":2}')
    second = build_continuous_assurance(tmp_path, baseline="baseline.json")
    assert second["changed"]
    (ev / "tool-execution-ledger-v40.json").write_text(json.dumps([{"status":"completed"},{"status":"failed"}]))
    metrics = build_benchmark_metrics(tmp_path)
    assert metrics["metrics"]["execution_success_rate"] == 0.5

def test_model_routing_and_attack_catalog(tmp_path):
    from modules.superior_capability_fabric_v311 import build_model_routing_plan, import_attack_emulation_catalog
    routing = build_model_routing_plan(tmp_path, "code-review")
    assert "ollama" in routing["providers"]
    assert routing["secret_storage"] == "none"
    stix = tmp_path / "attack.json"
    stix.write_text(json.dumps({"objects":[{"type":"attack-pattern","name":"Example Technique","external_references":[{"external_id":"T1001"}],"description":"example"}]}))
    out = import_attack_emulation_catalog(tmp_path, stix)
    assert out["count"] == 1
    assert out["techniques"][0]["id"] == "T1001"
    assert out["techniques"][0]["execution"] == "metadata-only"
