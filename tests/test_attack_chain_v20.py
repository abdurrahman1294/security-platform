import pytest

from modules.attack_chain_lab_v20 import run_lab_attack_chain


def test_attack_chain_requires_authorization(tmp_path):
    out = run_lab_attack_chain(tmp_path, authorized=False, execute=True, approval_token="x", roe_permitted=True)
    assert out["status"] == "blocked"
    assert out["stages"][-1]["status"] == "DENIED"


def test_attack_chain_dry_run_is_non_network(tmp_path):
    scope = tmp_path / "scope.txt"
    scope.write_text("127.0.0.1:8080\n127.0.0.1:8082\n")
    out = run_lab_attack_chain(tmp_path, authorized=True, execute=False, scope_file=scope)
    assert out["status"] == "dry_run"
    assert (tmp_path / "evidence" / "attack-chain-state.json").exists()


def test_attack_chain_rejects_non_loopback(tmp_path):
    with pytest.raises(ValueError, match="loopback-only"):
        run_lab_attack_chain(
            tmp_path, initial_url="https://example.com", authorized=True, execute=True,
            approval_token="x", roe_permitted=True
        )
