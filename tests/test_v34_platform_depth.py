import json
from pathlib import Path
from modules.assessment_normalizer_v34 import build as normalize
from modules.mission_planner_v34 import build as mission
from modules.evidence_quality_v34 import build as quality
from modules.retest_engine_v34 import compare
from modules.report_pack_v34 import build as report

def test_normalizer_merges_assets(tmp_path):
    (tmp_path/'recon').mkdir(); (tmp_path/'evidence').mkdir(); (tmp_path/'recon'/'live-hosts.txt').write_text('a.example\n')
    (tmp_path/'evidence'/'database-surface-v33.json').write_text(json.dumps({'services':[{'host':'a.example','port':5432,'service':'postgresql'}]}))
    d=normalize(tmp_path,'example.com')
    assert d['asset_count']==2 and any(x['port']==5432 for x in d['services'])

def test_mission_requires_authorization(tmp_path):
    d=mission(tmp_path,'example.com',authorized=False)
    assert d['phases'][0]['decision']=='BLOCKED'

def test_quality_hashes(tmp_path):
    (tmp_path/'evidence').mkdir(); (tmp_path/'evidence'/'x.json').write_text('{}')
    d=quality(tmp_path); assert d['artifact_count']==1 and len(d['artifacts'][0]['sha256'])==64

def test_retest_compare(tmp_path):
    a=tmp_path/'a.json'; b=tmp_path/'b.json'; a.write_text(json.dumps([{'finding_id':'A'},{'finding_id':'B'}])); b.write_text(json.dumps([{'finding_id':'B'},{'finding_id':'C'}]))
    d=compare(tmp_path,a,b); assert d['fixed']==['a'] and d['introduced']==['c'] and d['unchanged']==['b']

def test_report_pack(tmp_path):
    (tmp_path/'evidence').mkdir(); (tmp_path/'reports').mkdir(); (tmp_path/'evidence'/'x.json').write_text(json.dumps({'findings':[{'id':'X'}]}))
    d=report(tmp_path,'example.com'); assert d['finding_records']==1 and Path(d['report']).exists()
