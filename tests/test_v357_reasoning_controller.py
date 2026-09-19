import json
from pathlib import Path

from modules.engagement_state_v357 import EngagementState
from modules.reasoning_controller_v357 import build


def test_state_kernel_is_durable_and_deduplicated(tmp_path):
    s = EngagementState(tmp_path)
    assert s.observation(kind="surface", source="test", artifact="recon", value={"present": True}, confidence=1.0)
    assert not s.observation(kind="surface", source="test", artifact="recon", value={"present": True}, confidence=1.0)
    s.task(action="recon", target="127.0.0.1", reason="missing", score=70, risk="R1")
    snap = s.snapshot()
    assert snap["observations"]
    assert snap["tasks"][0]["requires_approval"] == 1


def test_controller_plans_without_executing(tmp_path):
    (tmp_path / "evidence").mkdir()
    (tmp_path / "recon").mkdir()
    (tmp_path / "recon" / "subdomains.txt").write_text("127.0.0.1\n")
    (tmp_path / "recon" / "live-hosts.txt").write_text("http://127.0.0.1:8091\n")
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "urls.txt").write_text("http://127.0.0.1:8091/\n")
    (tmp_path / "evidence" / "candidate.json").write_text(json.dumps({"findings": [{"name": "synthetic-candidate"}]}))
    result = build(tmp_path, "http://127.0.0.1:8091", phase="web", authorized=True)
    assert result["execution"]["performed"] is False
    assert any(x["action"] == "vulnerability_candidate_scan" for x in result["next_tasks"])
    assert any(x["action"] == "controlled_validation" and x["requires_approval"] for x in result["next_tasks"])
    assert (tmp_path / "state" / "engagement.db").is_file()
    assert json.loads((tmp_path / "evidence" / "reasoning-controller-v357.json").read_text())["schema_version"] == "3.57.0"
