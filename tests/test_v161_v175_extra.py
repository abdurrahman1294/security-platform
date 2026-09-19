import json, tempfile
from pathlib import Path
from modules.security_hardening_v163_v170 import build_security_audit, build_runtime_policy
from modules.osint_quality_v165_v170 import build_osint_quality

def test_security_audit_passes():
    with tempfile.TemporaryDirectory() as d:
        (Path(d)/"a.py").write_text("print('ok')")
        x=json.loads(build_security_audit(d).read_text()); assert x["decision"]=="PASS"

def test_runtime_policy():
    with tempfile.TemporaryDirectory() as d:
        x=json.loads(build_runtime_policy(d).read_text()); assert x["controls"]["registered_tool_only"]

def test_osint_quality_missing_image():
    with tempfile.TemporaryDirectory() as d:
        x=json.loads(build_osint_quality(d,[str(Path(d)/"missing.jpg")]).read_text()); assert x["images"][0]["exists"] is False
