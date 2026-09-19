import json
from modules.complete_assessment_v63_v70 import build

def test_complete_stack(tmp_path):
    (tmp_path/'evidence').mkdir(); (tmp_path/'reports').mkdir(); (tmp_path/'ad').mkdir(); (tmp_path/'ports').mkdir()
    (tmp_path/'ports'/'nmap-top.nmap').write_text('80/tcp open http\n443/tcp open https\n22/tcp open ssh\n')
    (tmp_path/'ad'/'guide.txt').write_text('Domain: example.local\n')
    results=build(tmp_path,'Demo Client','example.test')
    assert len(results)==8
    d=json.loads((tmp_path/'evidence'/'complete-platform-v70.json').read_text())
    assert d['platform_version']=='V70'
    assert d['safety']['autonomous_exploitation'] is False
    assert d['safety']['credential_theft'] is False
    assert d['status']=='ASSESSMENT_COMPLETE_PENDING_HUMAN_REVIEW'
