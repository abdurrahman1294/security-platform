from pathlib import Path
from modules.adversarial_self_assessment_v326 import (
    VERSION, default_personal_surface, build_asset_dependency_graph,
    generate_hypotheses, build_chain_analysis, adversarial_test_matrix, DENIED
)

def test_version_and_surface():
    assert VERSION == "3.26.0"
    assets = default_personal_surface()
    assert len(assets) >= 10
    assert {"cellular_connection","computer","mobile_phone","social_account"} <= {a["type"] for a in assets}

def test_cross_domain_graph_has_identity_and_endpoint_edges():
    g = build_asset_dependency_graph(default_personal_surface())
    relations = {e["relation"] for e in g["edges"]}
    assert "identity-provider-or-recovery" in relations
    assert "host-boundary" in relations
    assert "application-boundary" in relations

def test_chain_reasoning_is_multistep_and_not_compromise_claim():
    hs = generate_hypotheses(default_personal_surface())
    assert hs
    assert all(len(h["chain"]) >= 3 for h in hs)
    assert all(h["do_not_claim_compromise"] for h in hs)

def test_evidence_does_not_create_denied_execution():
    hs = generate_hypotheses(default_personal_surface(), [{"id":"x","finding":"credential theft"}])
    assert all(h["safety_class"] in {"R1_bounded_discovery","R2_non_destructive_verify"} for h in hs)
    assert "credential_theft" in DENIED

def test_build_artifact(tmp_path: Path):
    out = build_chain_analysis(tmp_path, target="self-assessment", observations=[{"id":"obs1","status":"observed"}])
    assert out["schema_version"] == VERSION
    assert (tmp_path / "evidence" / "adversarial-self-assessment-v326.json").exists()
    assert out["reasoning"]["cross_domain"] is True

def test_adversarial_matrix():
    suite = adversarial_test_matrix()
    assert suite["scenario_count"] >= 20
    assert "never_expand_scope" in suite["invariants"]

def test_v325_runtime_blocks_execution_without_authorization(tmp_path: Path):
    from modules.capability_runtime_v325 import run_bounded_runtime
    out = run_bounded_runtime(tmp_path, target="self-assessment", scope_file=tmp_path/"scope.csv", execute=True, authorized=False)
    assert out["status"] == "blocked"

def test_v325_runtime_does_not_select_incompatible_perspective():
    from modules.capability_runtime_v325 import select_next_capabilities
    out = select_next_capabilities(target="self", perspective="physical_lab", objective="full-assessment", limit=20)
    assert all(x["eligible"] for x in out)
    assert all(x["score"] >= 0 for x in out)

def test_v326_preserves_denied_classes_in_governance(tmp_path: Path):
    out = build_chain_analysis(tmp_path, target="self")
    denied=set(out["governance"]["automation_denied"])
    assert {"credential_theft","phishing","unrestricted_rce","carrier_bypass"} <= denied
