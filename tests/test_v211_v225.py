import json
from pathlib import Path
from modules.production_layer_v211_v225 import build_all

def test_v211_v225(tmp_path):
    d=build_all(tmp_path,'example.test')
    assert d['decision']=='PASS'
    ev=tmp_path/'evidence'
    assert json.loads((ev/'quality-gate-v225.json').read_text())['checks']
    assert (tmp_path/'reports'/'production-readiness-v225.md').exists()
    assert json.loads((ev/'tool-adapters-v212.json').read_text())['schema_version']=='212.0'
    assert json.loads((ev/'assessment-replay-v224.json').read_text())['replayable'] is True
