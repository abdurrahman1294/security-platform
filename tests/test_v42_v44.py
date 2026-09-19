import json
from pathlib import Path
from modules.pipeline_v42 import build_pipeline
from modules.result_collector_v43 import collect, load_results

def test_v42_pipeline_graph(tmp_path):
    e,r=build_pipeline(tmp_path,"example.test",scope_file="scope.txt")
    d=json.loads(e.read_text())
    assert d["tasks"][0]["action"]=="external-recon"
    assert d["tasks"][-1]["action"]=="vulnerability-discovery"
    assert r.exists()

def test_v43_collects_and_sanitizes(tmp_path):
    task={"task_id":"P42-test","action":"http-probe","tool":"httpx"}
    p=collect(tmp_path,task,"Authorization: Bearer SECRET\nok","",0,command=["httpx","-u","example.test"])
    d=json.loads(p.read_text())
    assert "SECRET" not in d["stdout"]
    assert len(load_results(tmp_path))==1

def test_v44_requires_registered_action(tmp_path):
    from modules.pipeline_runner_v44 import PipelineRunner
    r=PipelineRunner(tmp_path,"example.test")
    try: r._argv("not-a-real-action")
    except ValueError: pass
    else: assert False
