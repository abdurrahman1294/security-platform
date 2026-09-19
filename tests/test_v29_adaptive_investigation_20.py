import json
from pathlib import Path
from modules.adaptive_investigation_v29 import build

def test_v29_20_pass(tmp_path):
    ev=tmp_path/'evidence'; ev.mkdir()
    (tmp_path/'obs.json').write_text(json.dumps({'login':'present','api':'/api/v1','tcp/9001':'unknown protocol','workflow':'approval','aws':'iam role','android':'manifest','pcap':'ssid bssid','binary':'ELF'}))
    r=build(tmp_path,target='127.0.0.1',scope='scope.txt',authorized=True)
    checks=[
      r['schema_version']=='2.9', r['authorized_context'] is True, r['iteration']==1,
      len(r['environment']['signals'])==8, len(r['hypotheses'])==8, len(r['tasks'])==8,
      all(x['status']=='ready' for x in r['ready_tasks']),
      all(x['auto_execute'] is False for x in r['tasks']),
      all(x['requires_scope'] for x in r['tasks']), all(x['requires_operator'] for x in r['tasks']),
      len(r['escalations'])==2, r['loop']['replan'] is True,
      r['loop']['next_iteration_available'] is True, r['decision_policy']['no_scope_expansion'] is True,
      r['decision_policy']['no_arbitrary_payloads'] is True, r['decision_policy']['no_credential_guessing'] is True,
      r['decision_policy']['no_high_impact_auto_execution'] is True, r['decision_policy']['unknown_defaults_to_human'] is True,
      (ev/'adaptive-investigation-v29.json').exists(), (ev/'adaptive-next-actions-v29.json').exists(),
    ]
    assert all(checks), [i for i,x in enumerate(checks,1) if not x]

def test_v29_consumes_result_and_updates_state(tmp_path):
    (tmp_path/'evidence').mkdir(); (tmp_path/'obs.txt').write_text('login session API /api/v1')
    first=build(tmp_path)
    (tmp_path/'adaptive-result.json').write_text(json.dumps({'task_id':'T-api','status':'completed'}))
    second=build(tmp_path)
    task={x['id']:x for x in second['tasks']}['T-api']
    assert task['status']=='completed'
    assert second['iteration']==2
