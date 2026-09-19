import json
from pathlib import Path
from modules.cross_domain_attack_paths_v35 import build as paths
from modules.auth_role_analysis_v35 import build as roles
from modules.service_protocol_intelligence_v35 import build as services
from modules.remediation_tracking_v35 import build as remediation

def test_cross_domain_paths(tmp_path):
    (tmp_path/'evidence').mkdir()
    (tmp_path/'evidence/cloud-azure-assessment-v32.json').write_text(json.dumps({'findings':[{'id':'AZ-1','title':'identity exposure','asset':'sub'}]}))
    (tmp_path/'evidence/database-surface-v33.json').write_text(json.dumps({'services':[{'host':'db','port':5432,'service':'postgresql'}]}))
    out=paths(tmp_path); assert out['hypothesis_count']>=1

def test_role_mismatch(tmp_path):
    (tmp_path/'evidence').mkdir()
    p=tmp_path/'evidence/role-test-results.json'; p.write_text(json.dumps({'tests':[{'id':'t1','role':'user','expected':'deny','observed':'allow','evidence_ref':'ev1'}]}))
    out=roles(tmp_path); assert out['finding_count']==1

def test_protocol_intelligence(tmp_path):
    (tmp_path/'evidence').mkdir()
    (tmp_path/'evidence/normalized-attack-surface-v34.json').write_text(json.dumps({'services':[{'asset':'a','port':445,'service':'smb'},{'asset':'a','port':5432}]}))
    out=services(tmp_path); assert out['service_count']==2 and 'smb' in out['coverage']

def test_remediation_tracker(tmp_path):
    (tmp_path/'evidence').mkdir()
    (tmp_path/'evidence/normalized-findings.json').write_text(json.dumps({'findings':[{'normalized_id':'F1','severity':'high','title':'x'}]}))
    out=remediation(tmp_path); assert out['items'][0]['target_date'] and out['items'][0]['retest_required']
