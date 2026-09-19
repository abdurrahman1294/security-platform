"""Regression tests for two issues found in code review:

1. Scope-checked probing/validation code was following HTTP redirects via
   the default urllib opener, meaning a target that returns a 3xx to an
   out-of-scope host would cause the framework to make a real request to
   that unauthorized host while still reporting the pre-redirect URL as
   the thing that was "observed" / "scope_checked". modules/safe_http.py
   centralizes a non-redirect-following request path; these tests prove
   the out-of-scope host is never contacted.

2. Several modules (attack_graph, controlled_validation, exploit_planner_v35)
   carried their own duplicate copy of the nuclei array/JSONL parsing logic
   instead of using modules.findings_io.load_findings_file, and those copies
   didn't support the {"findings": [...]} wrapper format the shared loader
   does. They now delegate to the shared loader; these tests confirm the
   wrapper format works through each of them.
"""
import hashlib
import json
import threading
import http.server
import contextlib
from pathlib import Path

from modules.safe_http import request as safe_request


class _RedirectingHandler(http.server.BaseHTTPRequestHandler):
    """Always answers with a 302 to a configurable Location."""

    location = "http://127.0.0.9:1/unset"

    def do_HEAD(self):
        self.send_response(302)
        self.send_header("Location", self.location)
        self.end_headers()

    def do_GET(self):
        self.do_HEAD()

    def log_message(self, *_args):
        pass


class _RecordingHandler(http.server.BaseHTTPRequestHandler):
    """Records every hit it receives and answers 200."""

    hits = []

    def do_HEAD(self):
        self.__class__.hits.append(self.client_address)
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        self.do_HEAD()

    def log_message(self, *_args):
        pass


@contextlib.contextmanager
def _server(handler_cls, host, port):
    srv = http.server.HTTPServer((host, port), handler_cls)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield srv
    finally:
        srv.shutdown()
        t.join(timeout=2)


def test_safe_http_does_not_follow_redirects(tmp_path):
    _RecordingHandler.hits = []
    _RedirectingHandler.location = "http://127.0.0.5:8971/secret"
    with _server(_RecordingHandler, "127.0.0.5", 8971), \
         _server(_RedirectingHandler, "127.0.0.4", 8970):
        result = safe_request("http://127.0.0.4:8970/", method="HEAD")
    assert result["ok"] is True
    assert result["status"] == 302
    assert result.get("location") == "http://127.0.0.5:8971/secret"
    assert result.get("redirects_followed") is False
    assert _RecordingHandler.hits == [], (
        "safe_http.request followed a redirect to an unchecked host"
    )


def test_web_probe_v49_does_not_escape_scope_via_redirect(tmp_path):
    from modules.web_probe_v49 import run

    _RecordingHandler.hits = []
    _RedirectingHandler.location = "http://127.0.0.7:8973/secret"
    (tmp_path / "evidence").mkdir()
    (tmp_path / "reports").mkdir()
    (tmp_path / "evidence" / "web-test-matrix-v48.json").write_text(
        json.dumps({"tests": [{"test_case": "t1", "target": "http://127.0.0.6:8972/"}]})
    )
    scope = tmp_path / "scope.txt"
    scope.write_text("127.0.0.6\n")  # 127.0.0.7 is deliberately NOT in scope

    with _server(_RecordingHandler, "127.0.0.7", 8973), \
         _server(_RedirectingHandler, "127.0.0.6", 8972):
        ep, _rp = run(tmp_path, str(scope), approved=True)

    data = json.loads(ep.read_text())
    assert data["results"][0]["status"] == "observed"
    assert data["results"][0].get("location") == "http://127.0.0.7:8973/secret"
    assert _RecordingHandler.hits == [], (
        "web_probe_v49 made a live request to a host outside the scope file"
    )


def test_controlled_validation_does_not_escape_scope_via_redirect(tmp_path):
    from modules.controlled_validation import validate

    _RecordingHandler.hits = []
    _RedirectingHandler.location = "http://127.0.0.11:8975/secret"
    (tmp_path / "evidence").mkdir()
    (tmp_path / "reports").mkdir()
    (tmp_path / "vulns").mkdir()
    finding = {
        "template-id": "demo3",
        "info": {"name": "Demo3", "severity": "medium"},
        "matched-at": "http://127.0.0.10:8974/",
        "host": "http://127.0.0.10:8974/",
    }
    (tmp_path / "vulns" / "findings.json").write_text(json.dumps([finding]))
    scope = tmp_path / "scope.txt"
    scope.write_text("127.0.0.10\n")  # 127.0.0.11 is deliberately NOT in scope

    seed = "|".join(["demo3", "127.0.0.10", "http://127.0.0.10:8974/", "Demo3"])
    fid = "F-" + hashlib.sha256(seed.encode()).hexdigest()[:12]

    with _server(_RecordingHandler, "127.0.0.11", 8975), \
         _server(_RedirectingHandler, "127.0.0.10", 8974):
        result = validate(tmp_path, fid, "verify", str(scope), approved=True)

    assert result["result"] == "reachable-observed-redirect-not-followed"
    assert result["observations"][0].get("location") == "http://127.0.0.11:8975/secret"
    assert _RecordingHandler.hits == [], (
        "controlled_validation made a live request to a host outside the scope file"
    )


def test_attack_graph_loader_supports_findings_wrapper(tmp_path):
    from modules.attack_graph import load_findings

    (tmp_path / "vulns").mkdir()
    p = tmp_path / "vulns" / "findings.json"
    p.write_text(json.dumps({"findings": [{"template-id": "a"}, {"template-id": "b"}]}))
    found = load_findings(tmp_path)
    assert [f["template-id"] for f in found] == ["a", "b"]


def test_controlled_validation_loader_supports_findings_wrapper(tmp_path):
    from modules.controlled_validation import load_finding

    (tmp_path / "vulns").mkdir()
    p = tmp_path / "vulns" / "findings.json"
    p.write_text(json.dumps({"findings": [
        {"template-id": "wrapped-demo", "host": "example.com", "info": {"name": "Wrapped", "severity": "high"}},
    ]}))
    seed = "|".join(["wrapped-demo", "example.com", "example.com", "Wrapped"])
    fid = "F-" + hashlib.sha256(seed.encode()).hexdigest()[:12]
    found = load_finding(tmp_path, fid)
    assert found is not None
    assert found["template-id"] == "wrapped-demo"


def test_exploit_planner_v35_loader_supports_findings_wrapper(tmp_path):
    from modules.exploit_planner_v35 import load_findings

    (tmp_path / "evidence").mkdir()
    p = tmp_path / "evidence" / "normalized-findings.json"
    p.write_text(json.dumps({"findings": [{"finding_id": "F-1"}, {"finding_id": "F-2"}]}))
    found = load_findings(tmp_path)
    assert [f["finding_id"] for f in found] == ["F-1", "F-2"]
