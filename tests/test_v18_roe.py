from pathlib import Path
import json
from modules.autonomy_policy import AutonomyPolicy, Decision, RiskClass
from modules.roe_policy_v18 import ROEPolicy


def test_r4_requires_roe_and_approval():
    p = AutonomyPolicy(profile="assisted")
    assert p.risk_for("controlled_persistence_test") == RiskClass.R4
    assert p.decide("controlled_persistence_test", authorized=True, in_scope=True) == Decision.NEEDS_APPROVAL
    assert p.decide("controlled_persistence_test", authorized=True, in_scope=True, approval_token="x") == Decision.NEEDS_APPROVAL
    roe = ROEPolicy(enabled=True, allowed_actions={"controlled_persistence_test"})
    assert p.decide("controlled_persistence_test", authorized=True, in_scope=True, approval_token="x", roe_permitted=roe.permits("controlled_persistence_test")) == Decision.ALLOW_AUTO


def test_r5_is_permanently_denied():
    p = AutonomyPolicy(profile="assisted")
    for action in ("destructive_payload", "unrestricted_rce", "real_data_exfiltration"):
        assert p.decide(action, authorized=True, in_scope=True, approval_token="x", roe_permitted=True) == Decision.DENY


def test_roe_file_rejects_unknown_actions(tmp_path: Path):
    path = tmp_path / "roe.json"
    path.write_text(json.dumps({"enable_r4": True, "allowed_r4_actions": ["not_real"]}), encoding="utf-8")
    try:
        ROEPolicy.from_file(path)
    except ValueError:
        pass
    else:
        raise AssertionError("unknown R4 action must be rejected")
