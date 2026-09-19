from modules.universal_execution_graph_v323 import build_evidence_graph, build_execution_graph, generate_alternatives, score_candidates


def test_evidence_graph_redacts_secrets(tmp_path):
    out = build_evidence_graph(tmp_path, target='127.0.0.1', observations=[{'surface':'api','token':'secret','confidence':0.9}])
    raw = str(out)
    assert 'secret' not in raw
    assert out['observation_count'] == 1


def test_candidates_are_scored_and_governed(tmp_path):
    out = build_execution_graph(tmp_path, target='127.0.0.1', observations=[{'surface':'api','confidence':0.9}], surfaces=['api','firmware'], perspectives=['internet_ipv4'])
    assert out['status'] == 'ready'
    assert out['candidate_steps']
    assert out['governance']['authorization_required'] is True
    assert 'unrestricted_rce' in out['governance']['denied_autonomy_classes']


def test_failure_generates_alternatives():
    out = generate_alternatives(failed_step={'surface':'api','perspective':'internet_ipv4','reason':'timeout'}, max_alternatives=3)
    assert out
    assert all(x['perspective'] != 'internet_ipv4' for x in out if x['type'] == 'perspective-shift')


def test_coverage_tracks_completion():
    out = build_execution_graph(tmp_path := __import__('pathlib').Path('/tmp/v323-test'), target='127.0.0.1', surfaces=['api'], perspectives=['internet_ipv4','cellular_ipv4'], completed=[{'surface':'api','perspective':'internet_ipv4'}])
    assert out['coverage']['completed'] == 1
    assert out['coverage']['total'] == 2


def test_graph_run_requires_authorization(tmp_path):
    from modules.universal_execution_graph_v323 import run_execution_graph
    out = run_execution_graph(tmp_path, target='127.0.0.1', scope_file=tmp_path/'missing.csv', execute=True, authorized=False)
    assert out['status'] == 'blocked'


def test_graph_run_plan_only(tmp_path):
    from modules.universal_execution_graph_v323 import run_execution_graph
    scope = tmp_path/'scope.csv'; scope.write_text('127.0.0.1\n', encoding='utf-8')
    out = run_execution_graph(tmp_path, target='127.0.0.1', scope_file=scope, surfaces=['api'], perspectives=['testbed'], authorized=True, execute=False)
    assert out['status'] == 'plan-only'
    assert out['plan']['schema_version'] == '3.23.0'
