from modules.capability_runtime_v325 import VERSION, capability_catalog, select_next_capabilities, build_runtime_state, advance_runtime

def test_version_and_catalog():
    assert VERSION == "3.25.0"
    cats=capability_catalog()
    assert len(cats) >= 15
    assert all(c["risk"] in {"R0","R1","R2"} for c in cats)

def test_prerequisites_and_selection():
    xs=select_next_capabilities(target="127.0.0.1", perspective="internet_ipv4", objective="full-assessment", limit=5)
    ids={x["capability_id"] for x in xs}
    assert "surface-inventory" in ids
    assert "attack-path-review" not in ids

def test_state_and_advance(tmp_path):
    state=build_runtime_state(tmp_path,target="127.0.0.1",limit=4)
    assert state["schema_version"]==VERSION
    assert (tmp_path/"evidence"/"capability-runtime-v325.json").is_file()
    cid=state["next_capabilities"][0]["capability_id"]
    nxt=advance_runtime(tmp_path,target="127.0.0.1",capability_id=cid,result={"status":"completed"})
    assert cid in nxt["completed"]
    assert (tmp_path/"evidence"/"capability-runtime-state-v325.json").is_file()

def test_execution_requires_authorization(tmp_path):
    from modules.capability_runtime_v325 import run_bounded_runtime
    out=run_bounded_runtime(tmp_path,target="127.0.0.1",scope_file="missing",execute=True,authorized=False)
    assert out["status"]=="blocked"
