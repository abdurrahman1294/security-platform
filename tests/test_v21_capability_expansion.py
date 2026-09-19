import json
from pathlib import Path
import pytest
from modules.controlled_validation_v21 import validate
from modules.evidence_reasoner_v21 import reason
from modules.persistence_lab_v21 import run as persistence_run
from modules.lateral_movement_lab_v21 import run as lateral_run


def test_validation_is_loopback_only(tmp_path):
    with pytest.raises(ValueError):
        validate(tmp_path, "https://example.com")


def test_reasoner_uses_confirmed_evidence(tmp_path):
    (tmp_path / "evidence").mkdir()
    (tmp_path / "evidence" / "controlled-validation-v21.json").write_text(json.dumps({"results":[
        {"technique":"path_traversal","status":"CONFIRMED"},
        {"technique":"xss_reflection","status":"NOT_CONFIRMED"}
    ]}))
    out=reason(tmp_path)
    assert any(x["action"]=="credential_discovery" for x in out["decisions"])
    assert not any(x["trigger"]=="xss_reflection" for x in out["decisions"])


def test_persistence_blocks_remote(tmp_path):
    assert persistence_run(tmp_path, "https://example.com")["status"] == "blocked"


def test_lateral_blocks_remote(tmp_path):
    assert lateral_run(tmp_path, "http://127.0.0.1:8080", "https://example.com")["status"] == "blocked"
