import json
from pathlib import Path
from modules.temporal_digital_twin_v328 import *

def test_timeline_and_state(tmp_path):
    assets=[{"id":"cellular_connection","type":"cellular_connection"},{"id":"computer","type":"computer"}]
    out=build_v328_fabric(tmp_path,target="self",assets=assets,chains=[{"chain_id":"c1","chain":["cellular_connection","computer"],"priority":.8}],timeline=[{"id":"e1","timestamp":1,"asset":"cellular_connection","state":"reachable"},{"id":"e2","timestamp":2,"asset":"computer","state":"online"}])
    assert out["schema_version"]=="3.28.0"
    assert len(out["state_snapshots"])==2
    assert out["temporal_attack_paths"][0]["chain"]

def test_denied_payload_not_catalogued_as_safe():
    assert all(x["class"] not in DENIED for x in payload_assurance_catalog())
    r=validate_payload_request("unrestricted_rce","example",authorized=True,approved=True)
    assert not r["allowed"]

def test_secret_redaction():
    out=build_v328_fabric("/tmp",target="self",assets=[],timeline=[{"secret":"dont-store","asset":"x","state":"ok"}])
    text=json.dumps(out)
    assert "dont-store" not in text

def test_matrix():
    m=v328_test_matrix(); assert m["scenario_count"]==25
