from pathlib import Path

import modules.specialist_reasoning_loop_v369 as loop_mod
from modules.specialist_reasoning_loop_v369 import run_loop


class EmptySuccessEngine:
    class X:
        target = "127.0.0.1"
        output = Path("/tmp/v376-test")
    e = X()

    def probe(self):
        return {"returncode": 0, "stdout": "", "stderr": ""}

    def web(self):
        return {"status": "skipped", "reason": "synthetic"}

    def api(self):
        return {"status": "skipped", "reason": "synthetic"}


def test_zero_exit_code_without_artifact_is_not_evidence(tmp_path):
    EmptySuccessEngine.e.output = tmp_path
    original = loop_mod.select_specialists
    loop_mod.select_specialists = lambda **kwargs: [{"specialist": "web", "score": 1.0, "signals": ["web"]}]
    try:
        out = run_loop(engine=EmptySuccessEngine(), objective="web", authorized=True, max_rounds=1, max_specialists=1)
    finally:
        loop_mod.select_specialists = original

    action = out["rounds"][0]["actions"][0]
    assert action["status"] == "completed"
    assert action["execution_status"] == "completed"
    assert action["evidence_status"] == "none"
    assert action["evidence_produced"] is False
    assert action["outcome_detail"] == "execution-succeeded-no-evidence"
    assert out["convergence"]["successful_executions"] == 1
    assert out["convergence"]["completed_actions"] == 0
    assert out["convergence"]["evidence_producing_actions"] == 0
    assert out["rounds"][0]["information_gain"] == 0.0
    assert out["status"] == "partial"


class ArtifactEngine(EmptySuccessEngine):
    def probe(self):
        evidence = self.e.output / "evidence"
        evidence.mkdir(parents=True, exist_ok=True)
        (evidence / "probe-proof.json").write_text('{"observation":"known"}', encoding="utf-8")
        return {"returncode": 0, "stdout": "", "stderr": ""}


def test_nonempty_artifact_created_by_action_is_verified_as_evidence(tmp_path):
    ArtifactEngine.e.output = tmp_path
    original = loop_mod.select_specialists
    loop_mod.select_specialists = lambda **kwargs: [{"specialist": "web", "score": 1.0, "signals": ["web"]}]
    try:
        out = run_loop(engine=ArtifactEngine(), objective="web", authorized=True, max_rounds=1, max_specialists=1)
    finally:
        loop_mod.select_specialists = original

    action = out["rounds"][0]["actions"][0]
    assert action["evidence_status"] == "verified"
    assert action["evidence_produced"] is True
    assert action["evidence_artifacts"] == ["probe-proof.json"]
    assert out["convergence"]["completed_actions"] == 1
