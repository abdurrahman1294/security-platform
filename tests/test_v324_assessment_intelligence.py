import json, time
from pathlib import Path
from modules.universal_assessment_intelligence_v324 import (
    VERSION, normalize_evidence, evidence_quality, state_model,
    extract_findings, correlate_cross_domain, build_exposure_impact_chains,
    rank_attack_paths, generate_hypotheses, build_remediation_retest,
    build_detection_validation, build_v324_fabric, build_attack_paths,
)

def test_version_and_redaction():
    x=normalize_evidence([{"title":"api finding","token":"secret","nested":{"password":"x"}}])[0]
    assert VERSION=="3.24.0"
    assert x["token"]=="[REDACTED]" and x["nested"]["password"]=="[REDACTED]"

def test_quality_and_state_staleness():
    now=time.time()
    fresh={"id":"f","title":"fresh","validated":True,"timestamp":now}
    old={"id":"o","title":"old","timestamp":now-90000}
    st=state_model([fresh,old],now=now,ttl_seconds=86400)
    assert st["fresh_count"]==1 and st["stale_count"]==1 and st["revalidation_required"]
    assert evidence_quality(fresh)>.7

def test_cross_domain_and_paths():
    obs=[
      {"id":"a","surface":"api","title":"API auth exposure","validated":True,"confidence":.9,"severity":.8,"exploitability":.7,"impact":.8},
      {"id":"b","surface":"identity_directory","title":"identity auth control weakness","validated":True,"confidence":.8,"severity":.8,"exploitability":.6,"impact":.9},
    ]
    f=extract_findings(obs); c=correlate_cross_domain(f); paths=rank_attack_paths(f,c)
    assert len(f)==2 and c["edges"] and paths
    assert all(p["status"]=="candidate" for p in paths)

def test_supporting_layers():
    f=extract_findings([{"id":"x","surface":"external_web","title":"web vulnerability","validated":True,"severity":.8,"exploitability":.7,"impact":.8}])
    assert build_exposure_impact_chains(f)[0]["do_not_claim_exploited"]
    assert generate_hypotheses(f, {"stale_count":0})
    assert build_remediation_retest(f)[0]["retest"]["required"]
    assert build_detection_validation(f)[0]["status"]=="planned"

def test_full_fabric_writes_artifacts(tmp_path):
    out=build_v324_fabric(tmp_path,target="127.0.0.1",observations=[{"surface":"api","title":"API exposure","validated":True,"severity":.7}],objective="full-assessment")
    assert out["schema_version"]==VERSION
    assert (tmp_path/"evidence"/"assessment-intelligence-v324.json").is_file()
    assert (tmp_path/"evidence"/"assessment-report-v324.json").is_file()
    assert out["governance"]["planning_only"] is True

def test_attack_paths_entrypoint(tmp_path):
    out=build_attack_paths(tmp_path,target="127.0.0.1",observations=[{"surface":"api","title":"API issue"}])
    assert out["schema_version"]==VERSION and "attack_paths" in out
