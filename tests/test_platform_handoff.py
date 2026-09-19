from pathlib import Path
from security_platform.core.handoff import publish, load

def test_handoff_is_structured_and_local(tmp_path):
    publish(tmp_path, "osint", {"assets": ["api.example.com"]})
    data=load(tmp_path,"osint")
    assert data["producer"] == "osint"
    assert data["payload"]["assets"] == ["api.example.com"]

def test_handoff_is_consumed_as_untrusted_data(tmp_path):
    from security_platform.core.platform import SecurityPlatform
    from security_platform.core.engagement import Engagement
    p=SecurityPlatform(Engagement("Acme", "example.com", tmp_path))
    path=p.write_manifest()
    assert path.exists()
