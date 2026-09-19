from pathlib import Path
from modules.reliability_execution_integrity_v331 import (
    build_v331_fabric, make_operation, transition_operation, IntegrityError,
    check_state_invariants, recover_operations, v331_test_matrix, digest
)


def test_preflight_blocks_stale_authorization(tmp_path):
    out = build_v331_fabric(tmp_path, target="127.0.0.1", authorized=True, execute=True, authorization_current=False)
    assert out["status"] == "blocked"
    assert "authorization-not-current" in out["preflight"]["blockers"]


def test_atomic_artifact_and_digest(tmp_path):
    op = make_operation(target="127.0.0.1", action="validate")
    out = build_v331_fabric(tmp_path, target="127.0.0.1", operations=[op], canonical_state={"auth_token":"secret"})
    assert Path(tmp_path, "evidence/reliability-execution-v331.json").exists()
    assert "auth_token" not in str(out)
    assert len(out["canonical_state"]["state_digest"]) == 64
    assert digest({"a":1}) == digest({"a":1})


def test_operation_transitions_are_strict():
    op = make_operation(target="x", action="observe")
    op = transition_operation(op, "approved")
    op = transition_operation(op, "started")
    op = transition_operation(op, "completed")
    assert op["status"] == "completed"
    try:
        transition_operation(op, "started")
        assert False
    except IntegrityError:
        pass


def test_interrupted_operations_recover():
    op = transition_operation(make_operation(target="x", action="validate"), "approved")
    op = transition_operation(op, "started")
    recovered = recover_operations([op])
    assert recovered[0]["status"] == "failed"
    assert recovered[0]["recovery_required"] is True
    assert recovered[0]["failure"]["retryable"] is True


def test_invariants_detect_duplicate_ids():
    op = make_operation(target="x", action="observe")
    state = {"target":"x", "scope_locked":True, "authorization_current":True,
             "execute_requested":False, "operations":[op, dict(op)]}
    result = check_state_invariants(state)
    assert not result["valid"]
    assert "duplicate-operation-id" in result["violations"]


def test_budgets_are_bounded(tmp_path):
    out = build_v331_fabric(tmp_path, target="x", max_steps=1001)
    assert out["status"] == "blocked"
    assert "max_steps-out-of-range" in out["preflight"]["blockers"]


def test_matrix():
    m = v331_test_matrix()
    assert m["schema_version"] == "3.31.0"
    assert m["scenario_count"] >= 45
