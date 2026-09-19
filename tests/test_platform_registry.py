from security_platform.core.registry import all_specs, get

def test_specialist_registry_is_stable():
    assert [x.name for x in all_specs()] == ["bounty", "mobile", "osint", "pentest", "remote", "wireless"]
    assert get("pentest").active is True
    assert get("osint").active is True
