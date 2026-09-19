from modules.offensive_brain_v365 import build_brain_context, summarize_context

def test_story_and_evidence_context(tmp_path):
    (tmp_path/'evidence').mkdir()
    (tmp_path/'evidence'/'obs.json').write_text('{"note":"possible IDOR access control"}')
    c=build_brain_context(tmp_path,target='127.0.0.1',objective='test',story='I suspect IDOR')
    assert c['operator_story']=='I suspect IDOR'
    m=summarize_context(c)
    assert m['story_present'] is True
    assert any(x['class']=='access-control' for x in m['signals'])
