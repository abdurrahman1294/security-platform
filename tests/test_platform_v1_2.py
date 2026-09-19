from pathlib import Path
from security_platform.core.engagement import Engagement
from security_platform.core.platform import SecurityPlatform
from security_platform.core.registry import all_specs

def test_all_three_specialists_are_active_and_capable():
    specs = {s.name: s for s in all_specs()}
    assert set(specs) == {"osint", "pentest", "bounty", "mobile", "remote", "wireless"}
    assert all(s.active for s in specs.values())
    assert all(s.capabilities for s in specs.values())

def test_platform_manifest_describes_shared_authority_boundary(tmp_path):
    e = Engagement("Acme", "example.com", tmp_path)
    p = SecurityPlatform(e)
    path = p.write_manifest()
    assert path.exists()
    data = path.read_text(encoding="utf-8")
    assert "no engine can grant another engine permission to act" in data
