from fastapi.testclient import TestClient
import webapp.app as webapp

client = TestClient(webapp.app)


def mission(tmp_path, authorized=False):
    scope = tmp_path / "scope.txt"
    scope.write_text("127.0.0.1\n", encoding="utf-8")
    return {
        "client": "lab",
        "target": "127.0.0.1",
        "scope": str(scope),
        "output": str(tmp_path / "out"),
        "objective": "web API authorization assessment",
        "story": "compare role behavior",
        "authorized": authorized,
    }


def test_advisor_passes_supported_context_and_returns_json(tmp_path, monkeypatch):
    seen = {}

    def fake_advise(**kwargs):
        seen.update(kwargs)
        return {"ok": True, "context_used": kwargs["context"]}

    monkeypatch.setattr(webapp, "advise", fake_advise)
    r = client.post("/api/advisor", json={"mission": mission(tmp_path), "question": "What should I test first?"})
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert seen["target"] == "127.0.0.1"
    assert seen["engagement"] == "lab"
    assert seen["context"]["objective"].startswith("web API")
    assert seen["context"]["story"] == "compare role behavior"


def test_advisor_failure_is_structured_json(tmp_path, monkeypatch):
    def fake_advise(**kwargs):
        raise TypeError("synthetic advisor failure")

    monkeypatch.setattr(webapp, "advise", fake_advise)
    r = client.post("/api/advisor", json={"mission": mission(tmp_path), "question": "test"})
    assert r.status_code == 400
    assert r.json()["detail"] == "synthetic advisor failure"


def test_report_action_maps_to_existing_finalize(tmp_path, monkeypatch):
    class FakeEngine:
        def finalize(self):
            return {"status": "READY"}

    monkeypatch.setattr(webapp, "engine_for", lambda m: FakeEngine())
    r = client.post("/api/mission/action/report", json=mission(tmp_path, authorized=True))
    assert r.status_code == 200
    assert r.json()["result"]["status"] == "READY"


def test_named_action_mapping_matches_engine_surface():
    from security_platform.engines import PentestEngine
    mapping = {"discover": "recon", "ports": "ports", "probe": "probe", "web": "crawl_and_scan",
               "api": "api", "exploit": "exploitation_loop", "report": "finalize"}
    for action, method in mapping.items():
        assert callable(getattr(PentestEngine, method, None)), (action, method)


def test_health_version_is_current():
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["version"] == "4.1.0"


def test_ui_assets_are_not_cached(tmp_path):
    r = client.get("/")
    assert r.status_code == 200
    assert r.headers.get("cache-control") == "no-store, no-cache, must-revalidate, max-age=0"
    assert "app.js?v=4.1" in r.text


def test_static_assets_are_not_cached():
    r = client.get("/static/app.js?v=3.75")
    assert r.status_code == 200
    assert r.headers.get("cache-control") == "no-store, no-cache, must-revalidate, max-age=0"
