import json
from pathlib import Path
from modules.controlled_validation import validate


def _write_scope(path: Path):
    path.write_text("example.com\n", encoding="utf-8")


def test_cvm_requires_approval(tmp_path):
    scope = tmp_path / "scope.txt"
    _write_scope(scope)
    try:
        validate(tmp_path, "F-nope", "verify", scope, approved=False)
        assert False, "approval should be required"
    except PermissionError as exc:
        assert "approval" in str(exc).lower()


def test_cvm_impact_is_documentation_only(tmp_path):
    scope = tmp_path / "scope.txt"
    _write_scope(scope)
    (tmp_path / "vulns").mkdir()
    (tmp_path / "vulns" / "findings.json").write_text(
        json.dumps({"template-id": "demo", "host": "example.com", "info": {"name": "Demo", "severity": "high"}}) + "\n",
        encoding="utf-8",
    )
    result = validate(tmp_path, "F-" + __import__("hashlib").sha256(b"demo|example.com|example.com|Demo").hexdigest()[:12], "impact", scope, approved=True)
    assert result["destructive_actions"] is False
    assert result["exploit_payloads"] is False
    assert "documentation-only" in result["observations"][0]
    assert (tmp_path / "evidence" / "validation-ledger.json").exists()


def test_cvm_blocks_out_of_scope(tmp_path):
    scope = tmp_path / "scope.txt"
    _write_scope(scope)
    (tmp_path / "vulns").mkdir()
    (tmp_path / "vulns" / "findings.json").write_text(
        json.dumps({"template-id": "demo2", "host": "outside.example", "info": {"name": "Demo", "severity": "high"}}) + "\n",
        encoding="utf-8",
    )
    import hashlib
    fid = "F-" + hashlib.sha256(b"demo2|outside.example|outside.example|Demo").hexdigest()[:12]
    try:
        validate(tmp_path, fid, "verify", scope, approved=True)
        assert False, "out-of-scope target should be blocked"
    except PermissionError as exc:
        assert "scope" in str(exc).lower()
