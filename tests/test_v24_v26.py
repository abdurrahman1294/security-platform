import json
from modules.data_normalization_v24 import build as normalize
from modules.finding_dedup_v25 import build as dedup
from modules.remediation_intelligence_v26 import build as remediate

def seed(root):
    for d in ['vulns','api','evidence','reports']:(root/d).mkdir(parents=True,exist_ok=True)
    f={'template-id':'xss-1','host':'https://app.local/path','info':{'name':'Cross Site Scripting','severity':'high','description':'reflected xss'}}
    f2={'template-id':'xss-1','host':'https://app.local/path','info':{'name':'Cross Site Scripting','severity':'high','description':'reflected xss'}}
    (root/'vulns'/'findings.json').write_text(json.dumps(f)+'\n')
    (root/'api'/'api-findings.json').write_text(json.dumps(f2)+'\n')
    (root/'evidence'/'business-impact.json').write_text(json.dumps({}))

def test_v24_v26(tmp_path):
    seed(tmp_path)
    p=normalize(tmp_path); d=json.loads(p.read_text()); assert d['records_seen']==2 and d['records_normalized']==1
    p=dedup(tmp_path); d=json.loads(p.read_text()); assert d['clusters'] and isinstance(d['history'],dict)
    p=remediate(tmp_path); d=json.loads(p.read_text()); assert d['recommendations'][0]['root_cause_category']=='injection'
