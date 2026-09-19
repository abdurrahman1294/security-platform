from pathlib import Path
from modules.universal_specialist_router_v322 import build_specialist_router, build_r4_capability_matrix, execute_universal_router


def scope(tmp_path):
    p=tmp_path/'scope.csv'; p.write_text('127.0.0.1\n', encoding='utf-8'); return p


def test_all_surfaces_route(tmp_path):
    out=build_specialist_router(tmp_path, target='127.0.0.1', perspective='testbed')
    assert out['coverage']['selected'] == 35
    assert out['coverage']['unmapped'] == 0


def test_r4_matrix_is_governed(tmp_path):
    out=build_r4_capability_matrix(tmp_path, target='127.0.0.1')
    actions={x['action'] for x in out['r4']}
    assert 'controlled_attack_chain_test' in actions
    assert 'unrestricted_rce' in out['not_implemented']


def test_router_plan_only_delegates(tmp_path):
    out=execute_universal_router(tmp_path, target='127.0.0.1', scope_file=scope(tmp_path), perspective='cellular_ipv6', authorized=True, execute=False, surfaces=['firmware','external_web'])
    assert out['status'] == 'plan-only'
    assert out['universal_safe_execution']['coverage']['skipped'] >= 1
    assert out['specialist_delegation'][0]['status'] == 'delegated'

def test_r4_real_target_delegates(tmp_path):
    from modules.universal_specialist_router_v322 import execute_r4_controlled
    from modules.approval_queue import ApprovalQueue
    q=ApprovalQueue(tmp_path/'evidence'); req=q.submit('controlled_privilege_escalation_test','192.0.2.10','test',risk='R4'); token=q.approve(req.request_id)
    out=execute_r4_controlled(tmp_path, target='192.0.2.10', scope_file=scope(tmp_path), action='controlled_privilege_escalation_test', authorized=True, roe_permitted=True, approval_token=token, approval_request_id=req.request_id, perspective='internet_ipv4')
    assert out['status'] == 'specialist-required'


def test_r4_lab_requires_distinct_target_for_lateral(tmp_path):
    from modules.universal_specialist_router_v322 import execute_r4_controlled
    from modules.approval_queue import ApprovalQueue
    q=ApprovalQueue(tmp_path/'evidence'); req=q.submit('controlled_lateral_movement_test','127.0.0.1','test',risk='R4'); token=q.approve(req.request_id)
    out=execute_r4_controlled(tmp_path, target='127.0.0.1', scope_file=scope(tmp_path), action='controlled_lateral_movement_test', authorized=True, roe_permitted=True, approval_token=token, approval_request_id=req.request_id, perspective='testbed')
    assert out['status'] == 'blocked'

def test_r4_approval_token_is_single_use(tmp_path):
    from modules.universal_specialist_router_v322 import execute_r4_controlled
    from modules.approval_queue import ApprovalQueue
    q=ApprovalQueue(tmp_path/'evidence')
    req=q.submit('controlled_privilege_escalation_test','127.0.0.1','test',risk='R4')
    token=q.approve(req.request_id)
    first=execute_r4_controlled(tmp_path, target='127.0.0.1', scope_file=scope(tmp_path), action='controlled_privilege_escalation_test', authorized=True, roe_permitted=True, approval_token=token, approval_request_id=req.request_id, perspective='testbed')
    second=execute_r4_controlled(tmp_path, target='127.0.0.1', scope_file=scope(tmp_path), action='controlled_privilege_escalation_test', authorized=True, roe_permitted=True, approval_token=token, approval_request_id=req.request_id, perspective='testbed')
    assert first['status'] == 'completed'
    assert second['status'] == 'blocked'
    assert second['reason'] == 'invalid_or_consumed_approval_token'
