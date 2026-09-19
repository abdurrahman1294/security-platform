from pathlib import Path
from modules.adversarial_reasoning_v327 import (
    VERSION, normalize_evidence, detect_evidence_conflicts, evidence_resilience,
    enumerate_chains, build_deep_reasoning, adversarial_reasoning_test_suite, DENIED,
)
from modules.adversarial_self_assessment_v326 import default_personal_surface, build_asset_dependency_graph


def test_version_and_deep_chain_generation():
    assets = default_personal_surface()
    graph = build_asset_dependency_graph(assets)
    chains = enumerate_chains(graph, max_length=8, max_chains=40)
    assert VERSION == "3.27.0"
    assert chains and max(map(len, chains)) >= 3


def test_secret_fields_are_redacted_and_freshness_applied():
    e = normalize_evidence([{"id":"x", "finding":"weak recovery", "password":"secret", "trust":"external", "observed_at":0}])
    assert "password" not in e[0]
    assert 0 <= e[0]["freshness"] <= 1


def test_conflict_is_preserved_not_resolved_by_guessing():
    e = normalize_evidence([
        {"id":"a", "claim":"service reachable", "trust":"provider"},
        {"id":"b", "claim":"service unreachable", "trust":"external"},
    ])
    c = detect_evidence_conflicts(e)
    assert c
    assert c[0]["resolution"].startswith("retain both")


def test_untrusted_evidence_cannot_override_authoritative():
    e = normalize_evidence([
        {"id":"a", "claim":"service present", "trust":"authoritative"},
        {"id":"b", "claim":"service absent", "trust":"external"},
    ])
    r = evidence_resilience(e)
    assert r["poisoning_resistance"]["untrusted_cannot_override_authoritative"]
    assert r["conflict_count"] >= 1


def test_build_reasoning_preserves_uncertainty_and_denied_classes(tmp_path: Path):
    out = build_deep_reasoning(tmp_path, target="self", assets=default_personal_surface(), observations=[
        {"id":"obs1", "claim":"cellular egress reachable", "trust":"instrument"},
    ])
    assert out["schema_version"] == VERSION
    assert out["reasoning"]["deep_chain_search"]
    assert all(x["do_not_claim_compromise"] for x in out["chains"])
    assert "unrestricted_rce" in out["governance"]["automation_denied"]
    assert (tmp_path / "evidence" / "adversarial-deep-reasoning-v327.json").exists()


def test_suite_is_broader_than_v326():
    suite = adversarial_reasoning_test_suite()
    assert suite["scenario_count"] >= 25
    assert "preserve_uncertainty" in suite["invariants"]
    assert "no_secret_values_in_reasoning_artifacts" in suite["invariants"]
