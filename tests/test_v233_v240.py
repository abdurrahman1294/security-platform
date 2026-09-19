import json
from pathlib import Path
from modules.osint_orchestrator_v233 import build as osint_plan
from modules.osint_ingest_v234 import ingest as osint_ingest
from modules.osint_correlation_v235 import build as osint_corr
from modules.osint_gap_engine_v236 import build as osint_gap
from modules.osint_intelligence_report_v237 import build as osint_report
from modules.osint_entity_graph_v201 import build as osint_graph
from modules.osint_social_sources_v202 import build as osint_social
from modules.image_analysis_v203 import build as osint_image
from modules.osint_timeline_v204 import build as osint_timeline
from modules.osint_source_corroboration_v205 import build as osint_corroborate
from modules.bug_bounty_program_v238 import build as bb_policy
from modules.bug_bounty_planner_v239 import build as bb_plan
from modules.bug_bounty_quality_v240 import build as bb_quality

def test_osint_excellence_pipeline(tmp_path):
    (tmp_path/'evidence').mkdir(); (tmp_path/'reports').mkdir()
    tool=tmp_path/'subfinder.jsonl'; tool.write_text('{"host":"api.example.com","source":"subfinder"}\n{"host":"api.example.com","source":"certificate-transparency"}\n')
    osint_plan(tmp_path,'example.com','infrastructure and attack surface')
    osint_ingest(tmp_path,[tool]); corr=osint_corr(tmp_path); gap=osint_gap(tmp_path); report=osint_report(tmp_path,'example.com')
    assert corr['entity_count'] == 1
    assert gap['coverage_percent'] >= 0
    assert report['high_confidence_entities'][0]['value'] == 'api.example.com'
    osint_graph(tmp_path, [{'type':'domain','value':'example.com','source':'ct','confidence':'high'}])
    osint_social(tmp_path); osint_image(tmp_path); osint_timeline(tmp_path); osint_corroborate(tmp_path, [{'claim':'api.example.com is related','evidence':[{'source':'ct'},{'source':'dns'}]}])
    assert (tmp_path/'evidence'/'osint-entity-graph-v201.json').exists()

def test_bounty_excellence_pipeline(tmp_path):
    (tmp_path/'evidence').mkdir(); (tmp_path/'reports').mkdir()
    policy=tmp_path/'program.json'; policy.write_text(json.dumps({'scope':['example.com','api.example.com'],'exclusions':['admin.example.com'],'allowed_testing':['in_scope_http'],'forbidden':['dos'],'rate_limit':'5 req/s'}))
    bb_policy(tmp_path,'Example Program',str(policy),['example.com'])
    plan=bb_plan(tmp_path,'example.com'); gate=bb_quality(tmp_path)
    assert 'api.example.com' in plan['assets']
    assert any(x['category']=='authorization' for x in plan['plan'])
    assert gate['submission']=='never automatic'
