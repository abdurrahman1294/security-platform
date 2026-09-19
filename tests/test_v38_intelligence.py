import json
from modules.intelligence_fabric_v38 import *
from modules.engagement_orchestration_v38 import build

def seed(tmp):
    ev=tmp/"evidence"; ev.mkdir()
    (ev/"asset-identity-v37.json").write_text(json.dumps({"identities":[
      {"asset_id":"A-a","canonical":"app.example","aliases":[]},
      {"asset_id":"A-b","canonical":"api.example","aliases":[]},
      {"asset_id":"A-c","canonical":"db.example","aliases":[]}] }))
    (ev/"dependency-map-v37.json").write_text(json.dumps({"edges":[
      {"src":"A-a","dst":"A-b","relationship":"backend","confidence":0.9},
      {"src":"A-b","dst":"A-c","relationship":"database","confidence":0.8}]}))
    (ev/"normalized-findings.json").write_text(json.dumps({"findings":[
      {"normalized_id":"F1","asset":"app.example","severity":"high","url":"https://app.example/x","source":"scanner"},
      {"normalized_id":"F2","asset":"db.example","severity":"critical","evidence":"sample","validation_state":"validated"}]}))
    (ev/"authenticated-evidence-v37.json").write_text(json.dumps({"tests":[{"role":"user","asset":"app.example","mismatch":True}]}))
    (ev/"remediation-priority-v37.json").write_text(json.dumps({"items":[{"finding_id":"F1","asset":"app.example","priority_score":90}]}))
    (ev/"evidence-quality-v34.json").write_text(json.dumps({"score":80}))

def test_asset_context(tmp_path): seed(tmp_path); o=asset_context(tmp_path); assert len(o["assets"])==3

def test_asset_criticality_deterministic(tmp_path): seed(tmp_path); a=asset_context(tmp_path); b=asset_context(tmp_path); assert a==b

def test_multihop_has_two_hops(tmp_path): seed(tmp_path); asset_context(tmp_path); o=multi_hop_paths(tmp_path); assert any(len(x["nodes"])==3 for x in o["paths"])

def test_multihop_max_hops(tmp_path): seed(tmp_path); asset_context(tmp_path); o=multi_hop_paths(tmp_path,1); assert all(len(x["nodes"])<=2 for x in o["paths"])

def test_multihop_does_not_self_loop(tmp_path): seed(tmp_path); asset_context(tmp_path); o=multi_hop_paths(tmp_path); assert all(len(x["nodes"])==len(set(x["nodes"])) for x in o["paths"])

def test_confidence_calibration(tmp_path): seed(tmp_path); o=calibrate_findings(tmp_path); assert len(o["findings"])==2

def test_confirmed_requires_validation(tmp_path): seed(tmp_path); o=calibrate_findings(tmp_path); assert all(x["state"]!="confirmed" for x in o["findings"] if x["finding_id"]=="F1")

def test_validated_can_remain_validated(tmp_path): seed(tmp_path); o=calibrate_findings(tmp_path); assert next(x for x in o["findings"] if x["finding_id"]=="F2")["state"]=="validated"

def test_provenance_chain(tmp_path): seed(tmp_path); o=provenance_chain(tmp_path); assert o["entry_count"]>=4

def test_provenance_links_chain(tmp_path): seed(tmp_path); o=provenance_chain(tmp_path); assert o["chain"][0]["previous"]=="GENESIS"

def test_remediation_dependency_priority(tmp_path): seed(tmp_path); asset_context(tmp_path); o=remediation_dependencies(tmp_path); assert o["items"][0]["retest_required"] is True

def test_remediation_score_not_decreased(tmp_path): seed(tmp_path); asset_context(tmp_path); o=remediation_dependencies(tmp_path); assert o["items"][0]["adjusted_score"]>=90

def test_session_model(tmp_path): seed(tmp_path); o=session_model(tmp_path); assert o["count"]==1

def test_session_no_secret_storage(tmp_path): seed(tmp_path); o=session_model(tmp_path); assert all("password" not in json.dumps(x).lower() and "token_value" not in json.dumps(x).lower() for x in o["sessions"])

def test_plugin_contract_empty_is_valid_catalog(tmp_path): seed(tmp_path); o=plugin_contract(tmp_path); assert o["required_fields"]

def test_plugin_contract_rejects_incomplete(tmp_path):
    seed(tmp_path); p=tmp_path/"plugins"; p.mkdir(); (p/"bad.json").write_text(json.dumps({"name":"x"})); o=plugin_contract(tmp_path); assert o["plugins"][0]["valid"] is False

def test_plugin_contract_accepts_complete(tmp_path):
    seed(tmp_path); p=tmp_path/"plugins"; p.mkdir(); (p/"ok.json").write_text(json.dumps({k:{} for k in ["name","version","capabilities","input_schema","output_schema","safety","evidence"]})); o=plugin_contract(tmp_path); assert o["plugins"][0]["valid"] is True

def test_coverage_all_present_after_orchestration(tmp_path): seed(tmp_path); o=build(tmp_path); assert o["results"]["coverage"]["coverage"]==100.0

def test_orchestration_phase_order(tmp_path): seed(tmp_path); o=build(tmp_path); assert o["phases"][0]=="asset_context" and o["phases"][-1]=="coverage"

def test_orchestration_writes_artifacts(tmp_path): seed(tmp_path); build(tmp_path); assert (tmp_path/"evidence"/"multi-hop-attack-paths-v38.json").exists()

def test_path_confidence_bounded(tmp_path): seed(tmp_path); asset_context(tmp_path); o=multi_hop_paths(tmp_path); assert all(0<=x["confidence"]<=1 for x in o["paths"])
