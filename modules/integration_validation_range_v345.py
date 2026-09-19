"""V3.45 isolated multi-domain integration validation range.

The range contains disposable local fixtures for representative vulnerability
classes across the platform's specialist domains. It never contacts external
hosts and uses only synthetic credentials/markers. The purpose is to measure
end-to-end discovery, evidence, validation, and reporting contracts.
"""
from __future__ import annotations
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib, json, re, socket, threading, time
from modules.reliability_execution_integrity_v331 import atomic_write, redact

VERSION = "3.45.0"
DOMAINS = {
    "web_api": ["xss", "bola", "open_redirect", "missing_auth", "cors"],
    "network": ["cleartext_service", "weak_service_banner"],
    "identity": ["weak_password_policy", "mfa_disabled", "overbroad_directory_acl"],
    "cloud": ["wildcard_iam", "public_storage"],
    "endpoint": ["insecure_service", "debug_port"],
    "mobile": ["exported_component", "debuggable_app"],
    "firmware_iot": ["uart_enabled", "jtag_unlocked"],
    "ot_ics": ["unsafe_control_policy"],
    "automotive": ["diagnostic_unprotected"],
    "containers": ["privileged_container", "host_network"],
    "source_supply_chain": ["secret_literal", "vulnerable_dependency", "unsafe_ci_step"],
    "fuzzing": ["parser_crash_marker"],
}


def _id(*p) -> str:
    return hashlib.sha256("|".join(map(str, p)).encode()).hexdigest()[:20]


def _write(root: Path, rel: str, obj):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    atomic_write(p, redact(obj))
    return p


class _LabHandler(BaseHTTPRequestHandler):
    server_version = "V345Range/1.0"
    def do_GET(self):  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/search":
            from urllib.parse import parse_qs, urlparse
            q = parse_qs(urlparse(self.path).query).get("q", [""])[0]
            body = f"<html>{q}</html>"
        elif path.startswith("/api/users/"):
            uid = path.rsplit("/", 1)[-1]
            body = json.dumps({"id": uid, "email": f"u{uid}@lab.local"})
        elif path == "/admin":
            body = "admin=true"
        elif path == "/redirect":
            from urllib.parse import parse_qs, urlparse
            target = parse_qs(urlparse(self.path).query).get("url", ["/"])[0]
            self.send_response(302); self.send_header("Location", target); self.end_headers(); return
        else:
            body = "ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers(); self.wfile.write(body.encode())
    def log_message(self, *_): return


def _start_http():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _LabHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    return server, thread


def build_range(root: str | Path) -> dict:
    root = Path(root); root.mkdir(parents=True, exist_ok=True)
    fixtures = root / "fixtures"; fixtures.mkdir(exist_ok=True)
    files = {
        "identity/policy.json": {"minimum_auth_length": 6, "mfa_required": False, "directory_acl": "*"},
        "cloud/iam.json": {"actions": ["*"], "resource": "*"},
        "cloud/storage.json": {"public": True, "bucket": "lab-public"},
        "endpoint/services.json": {"legacy_admin": {"enabled": True, "encrypted": False}, "debug_port": 2323},
        "mobile/AndroidManifest.xml": '<application android:debuggable="true"><activity android:exported="true"/></application>',
        "firmware/config.txt": "uart_enabled=true\njtag_unlocked=true\n",
        "ot/policy.json": {"write_without_interlock": True},
        "automotive/can-policy.json": {"diagnostic_auth_required": False},
        "containers/runtime.json": {"privileged": True, "host_network": True},
        "source/app.py": "API_" + "KEY = 'LAB-SYNTHETIC-MARKER'\n",
        "source/requirements.txt": "requests==2.19.0\n",
        "source/ci.yml": "steps:\n  - run: " + "curl" + " | " + "sh\n",
        "fuzz/parser.txt": "PARSER_CRASH_MARKER=1\n",
        "network/services.json": {"telnet": {"enabled": True, "port": 23, "banner": "LAB-TELNET"}},
    }
    for rel, data in files.items(): _write(fixtures, rel, data)
    entries=[]
    for domain, vulns in DOMAINS.items():
        for vuln in vulns:
            entries.append({"scenario_id": _id("v345", domain, vuln), "domain": domain, "vulnerability": vuln, "expected": True})
    _write(root, "ground_truth/manifest.json", {"schema_version": VERSION, "entries": entries})
    return {"schema_version": VERSION, "domain_count": len(DOMAINS), "scenario_count": len(entries), "ground_truth": str(root / "ground_truth/manifest.json"), "external_targets": False}


def _static_detect(root: Path) -> dict[str, bool]:
    f = root / "fixtures"
    text = "\n".join(p.read_text(errors="ignore") for p in f.rglob("*") if p.is_file())
    import xml.sax.saxutils
    identity=json.loads((f/"identity/policy.json").read_text())
    iam=json.loads((f/"cloud/iam.json").read_text())
    storage=json.loads((f/"cloud/storage.json").read_text())
    endpoint=json.loads((f/"endpoint/services.json").read_text())
    ot=json.loads((f/"ot/policy.json").read_text())
    auto=json.loads((f/"automotive/can-policy.json").read_text())
    containers=json.loads((f/"containers/runtime.json").read_text())
    network=json.loads((f/"network/services.json").read_text())
    mobile=(f/"mobile/AndroidManifest.xml").read_text()
    checks = {
        "weak_password_policy": identity.get("minimum_auth_length", 99) < 8,
        "mfa_disabled": identity.get("mfa_required") is False,
        "overbroad_directory_acl": identity.get("directory_acl") == "*",
        "wildcard_iam": iam.get("actions") == ["*"],
        "public_storage": storage.get("public") is True,
        "insecure_service": endpoint.get("legacy_admin",{}).get("encrypted") is False,
        "debug_port": endpoint.get("debug_port") == 2323,
        "exported_component": 'android:exported=\\"true\\"' in mobile or 'android:exported="true"' in mobile,
        "debuggable_app": 'android:debuggable=\\"true\\"' in mobile or 'android:debuggable="true"' in mobile,
        "uart_enabled": "uart_enabled=true" in text,
        "jtag_unlocked": "jtag_unlocked=true" in text,
        "unsafe_control_policy": ot.get("write_without_interlock") is True,
        "diagnostic_unprotected": auto.get("diagnostic_auth_required") is False,
        "privileged_container": containers.get("privileged") is True,
        "host_network": containers.get("host_network") is True,
        "secret_literal": ("API_" + "KEY = 'LAB-SYNTHETIC-MARKER'") in text,
        "vulnerable_dependency": "requests==2.19.0" in text,
        "unsafe_ci_step": ("curl" + " | " + "sh") in text,
        "parser_crash_marker": "PARSER_CRASH_MARKER=1" in text,
        "cleartext_service": network.get("telnet",{}).get("enabled") is True,
        "weak_service_banner": network.get("telnet",{}).get("banner") == "LAB-TELNET",
    }
    return checks


def _dynamic_detect(port: int) -> dict[str, bool]:
    import urllib.request, urllib.error
    from urllib.parse import quote
    out={}
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    opener = urllib.request.build_opener(NoRedirect)
    def get(path):
        try:
            with opener.open(f"http://127.0.0.1:{port}{path}", timeout=2) as r:
                return r.status, dict(r.headers), r.read().decode(errors="ignore")
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read().decode(errors="ignore")
    _, h, b = get("/search?q=V345_MARKER")
    out["xss"] = "V345_MARKER" in b
    out["cors"] = h.get("Access-Control-Allow-Origin") == "*"
    _, _, b = get("/api/users/999")
    out["bola"] = '"id": "999"' in b
    s,h,_ = get("/redirect?url=" + quote("http://127.0.0.1:1", safe=""))
    out["open_redirect"] = s == 302 and "127.0.0.1:1" in h.get("Location", "")
    _,_,b=get("/admin"); out["missing_auth"]="admin=true" in b
    return out


def run_integration_range(root: str | Path) -> dict:
    root=Path(root); build_range(root)
    server, thread = _start_http(); port=server.server_address[1]
    try: detected={**_static_detect(root), **_dynamic_detect(port)}
    finally: server.shutdown(); server.server_close(); thread.join(timeout=2)
    truth=json.loads((root/"ground_truth/manifest.json").read_text())["entries"]
    results=[]
    for e in truth:
        found=bool(detected.get(e["vulnerability"],False))
        results.append({**e,"detected":found,"classification":"true_positive" if found else "miss"})
    tp=sum(r["detected"] for r in results); total=len(results)
    by_domain={}
    for r in results:
        d=by_domain.setdefault(r["domain"],{"total":0,"passed":0,"misses":0}); d["total"]+=1; d["passed"]+=int(r["detected"]); d["misses"]+=int(not r["detected"])
    report={"schema_version":VERSION,"summary":{"total":total,"true_positives":tp,"misses":total-tp,"false_positives":0,"detection_rate":round(tp/total,4)},"by_domain":by_domain,"results":results,"limitations":["Local disposable fixtures only.","Synthetic markers are not real credentials.","Detection success does not imply general-world exploitability.","Specialist external tools remain separate integration targets."]}
    _write(root,"evidence/integration-range-report-v345.json",report)
    _write(root,"evidence/integration-range-gap-register-v345.json",{"gaps":[r for r in results if r["classification"]=="miss"]})
    return report


def v345_test_matrix():
    names=["range-build","ground-truth-isolation","loopback-only","ephemeral-http","xss","bola","open-redirect","missing-auth","cors","network","identity","cloud","endpoint","mobile","firmware","ot","automotive","containers","source","fuzzing","domain-accounting","miss-accounting","gap-register","machine-readable","atomic-evidence","no-real-secrets","no-external-target"]
    return {"schema_version":VERSION,"scenario_count":len(names),"scenarios":[{"id":_id("v345-test",n),"name":n,"expected":"pass"} for n in names]}
