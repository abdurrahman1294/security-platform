from modules.agentic_executor_v363 import execute_actions


def test_executor_rechecks_scope_and_authorization():
    actions=[{"tool":"nmap","target":"10.0.0.8","args":[],"objective":"probe"}]
    a=execute_actions('/tmp', actions, target='10.0.0.8', in_scope=lambda x: False, authorized=True)
    assert a['receipts'][0]['reason']=='out-of-scope'
    b=execute_actions('/tmp', actions, target='10.0.0.8', in_scope=lambda x: True, authorized=False)
    assert b['receipts'][0]['reason']=='authorization-required'


def test_executor_rejects_unregistered_tool_before_process_start():
    actions=[{"tool":"arbitrary-shell","target":"127.0.0.1","args":["id"]}]
    out=execute_actions('/tmp', actions, target='127.0.0.1', in_scope=lambda x: True, authorized=True)
    assert out['receipts'][0]['reason']=='unregistered-tool'
