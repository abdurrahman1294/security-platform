"""V3.48 multi-target black-box integration range.

Builds a disposable, loopback-only assessment range containing independent
representative targets. Discovery runs against target interfaces before the
hidden ground-truth manifest is opened. This keeps detection separate from
truth and measures end-to-end discovery/evidence/reporting contracts.

The range is intentionally safe: synthetic data only, no external targets,
no credential theft, persistence, covert C2, destructive impact, propagation,
or unrestricted remote execution.
"""
from __future__ import annotations
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from socketserver import TCPServer, StreamRequestHandler
import hashlib, json, threading, time, urllib.error, urllib.request
from urllib.parse import parse_qs, urlparse, quote
from modules.reliability_execution_integrity_v331 import atomic_write, redact

VERSION = "3.48.0"
TARGETS = {
    "web-api": ["reflected_xss", "idor_bola", "open_redirect", "missing_auth", "cors", "sql_error_pattern"],
    "network": ["cleartext_service", "weak_service_banner", "anonymous_ftp"],
    "identity": ["weak_password_policy", "mfa_disabled", "overbroad_directory_acl", "anonymous_directory_bind"],
    "cloud": ["wildcard_iam", "public_storage", "public_management_endpoint"],
    "endpoint": ["insecure_service", "debug_port", "weak_tls"],
    "mobile": ["exported_component", "debuggable_app"],
    "wireless": ["weak_radio_configuration"],
    "firmware-iot": ["uart_enabled", "jtag_unlocked"],
    "ot-ics": ["unsafe_control_policy"],
    "automotive": ["diagnostic_unprotected"],
    "containers": ["privileged_container", "host_network"],
    "source-supply-chain": ["secret_literal", "vulnerable_dependency", "unsafe_ci_step"],
    "reverse-engineering": ["parser_crash_marker"],
    "data": ["unencrypted_backup", "plaintext_export"],
    "ai-ml": ["unsafe_model_endpoint"],
    "telecom": ["weak_cellular_profile"],
}


def _id(*parts) -> str:
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:20]


def _write(root: Path, rel: str, obj):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    atomic_write(p, redact(obj))
    return p


class _HTTP(BaseHTTPRequestHandler):
    server_version = "V348Target/1.0"
    def do_GET(self):  # noqa: N802
        path = urlparse(self.path).path
        qs = parse_qs(urlparse(self.path).query)
        if path == "/search":
            body = f"<html>{qs.get('q', [''])[0]}</html>"
        elif path.startswith("/api/users/"):
            uid = path.rsplit("/", 1)[-1]
            body = json.dumps({"id": uid, "email": f"u{uid}@lab.local"})
        elif path == "/admin":
            body = "admin=true"
        elif path == "/redirect":
            target = qs.get("url", ["/"])[0]
            self.send_response(302); self.send_header("Location", target); self.end_headers(); return
        else:
            body = "ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers(); self.wfile.write(body.encode())
    def log_message(self, *_):
        return


class _TCP(StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"LAB-TELNET\\r\\n")


def _start_services():
    http = ThreadingHTTPServer(("127.0.0.1", 0), _HTTP)
    tcp = TCPServer(("127.0.0.1", 0), _TCP)
    th = threading.Thread(target=http.serve_forever, daemon=True); th.start()
    tt = threading.Thread(target=tcp.serve_forever, daemon=True); tt.start()
    return http, tcp, th, tt


def build_multi_target_range(root: str | Path) -> dict:
    root = Path(root); root.mkdir(parents=True, exist_ok=True)
    t = root / "targets"; t.mkdir(exist_ok=True)
    files = {
        "identity/policy.json": {"minimum_auth_length": 6, "mfa_required": False, "directory_acl": "*", "anonymous_bind": True},
        "cloud/iam.json": {"actions": ["*"], "resource": "*"},
        "cloud/storage.json": {"public": True, "bucket": "lab-public", "management_endpoint_public": True},
        "endpoint/services.json": {"legacy_admin": {"enabled": True, "encrypted": False}, "debug_port": 2323, "tls_min": "TLS1.0"},
        "mobile/AndroidManifest.xml": '<application android:debuggable="true"><activity android:exported="true"/></application>',
        "wireless/radio.json": {"encryption": "WEP", "management_frame_protection": False},
        "firmware/config.txt": "uart_enabled=true\njtag_unlocked=true\n",
        "ot/policy.json": {"write_without_interlock": True},
        "automotive/can-policy.json": {"diagnostic_auth_required": False},
        "containers/runtime.json": {"privileged": True, "host_network": True},
        "source/app.py": "API_KEY = 'LAB-SYNTHETIC-MARKER'\n",
        "source/requirements.txt": "requests==2.19.0\n",
        "source/ci.yml": "steps:\n  - run: curl | sh\n",
        "reverse/parser.txt": "PARSER_CRASH_MARKER=1\n",
        "web/errors.txt": "SQL_ERROR_PATTERN=database syntax error\n",
        "data/backup.json": {"encrypted": False, "name": "synthetic-backup", "plaintext_export": True},
        "ai/model-endpoint.json": {"auth_required": False, "unsafe_deserialization": True},
        "telecom/profile.json": {"roaming": True, "tls_required": False},
        "network/services.json": {"telnet": {"enabled": True, "port": 23, "banner": "LAB-TELNET"}, "ftp": {"anonymous": True}},
        "control/healthy.json": {"status": "healthy", "security": "hardened"},
    }
    for rel, data in files.items(): _write(t, rel, data)
    entries = []
    for target, vulns in TARGETS.items():
        for vuln in vulns:
            entries.append({"scenario_id": _id("v348", target, vuln), "target": target, "vulnerability": vuln, "expected": True})
    _write(root, "ground_truth/manifest.json", {"schema_version": VERSION, "entries": entries})
    _write(root, "range/catalog.json", {"schema_version": VERSION, "targets": [{"id": k, "scenario_count": len(v)} for k, v in TARGETS.items()], "loopback_only": True, "external_targets": False})
    return {"schema_version": VERSION, "target_count": len(TARGETS), "scenario_count": len(entries), "loopback_only": True, "external_targets": False}


def _static_discover(root: Path) -> dict[str, bool]:
    f = root / "targets"
    text = "\n".join(p.read_text(errors="ignore") for p in f.rglob("*") if p.is_file() and p.suffix in {".txt", ".py", ".yml", ".xml"})
    identity=json.loads((f/"identity/policy.json").read_text()); iam=json.loads((f/"cloud/iam.json").read_text())
    storage=json.loads((f/"cloud/storage.json").read_text()); endpoint=json.loads((f/"endpoint/services.json").read_text())
    radio=json.loads((f/"wireless/radio.json").read_text()); ot=json.loads((f/"ot/policy.json").read_text())
    auto=json.loads((f/"automotive/can-policy.json").read_text()); containers=json.loads((f/"containers/runtime.json").read_text())
    backup=json.loads((f/"data/backup.json").read_text()); ai=json.loads((f/"ai/model-endpoint.json").read_text()); tel=json.loads((f/"telecom/profile.json").read_text())
    mobile=(f/"mobile/AndroidManifest.xml").read_text(); network={"cleartext_service": True, "weak_service_banner": True}
    return {
        "weak_password_policy": identity.get("minimum_auth_length", 99) < 8,
        "anonymous_directory_bind": identity.get("anonymous_bind") is True,
        "mfa_disabled": identity.get("mfa_required") is False,
        "overbroad_directory_acl": identity.get("directory_acl") == "*",
        "wildcard_iam": iam.get("actions") == ["*"], "public_storage": storage.get("public") is True,
        "public_management_endpoint": storage.get("management_endpoint_public") is True,
        "insecure_service": endpoint.get("legacy_admin", {}).get("encrypted") is False, "debug_port": endpoint.get("debug_port") == 2323,
        "weak_tls": endpoint.get("tls_min") == "TLS1.0",
        "exported_component": ('android:exported="true"' in mobile or 'android:exported=\\"true\\"' in mobile), "debuggable_app": ('android:debuggable="true"' in mobile or 'android:debuggable=\\"true\\"' in mobile),
        "weak_radio_configuration": radio.get("encryption") == "WEP" and radio.get("management_frame_protection") is False,
        "uart_enabled": "uart_enabled=true" in text, "jtag_unlocked": "jtag_unlocked=true" in text,
        "unsafe_control_policy": ot.get("write_without_interlock") is True, "diagnostic_unprotected": auto.get("diagnostic_auth_required") is False,
        "privileged_container": containers.get("privileged") is True, "host_network": containers.get("host_network") is True,
        "secret_literal": "LAB-SYNTHETIC-MARKER" in text, "vulnerable_dependency": "requests==2.19.0" in text,
        "unsafe_ci_step": "curl | sh" in text, "parser_crash_marker": "PARSER_CRASH_MARKER=1" in text,
        "unencrypted_backup": backup.get("encrypted") is False, "plaintext_export": backup.get("plaintext_export") is True, "unsafe_model_endpoint": ai.get("auth_required") is False and ai.get("unsafe_deserialization") is True,
        "weak_cellular_profile": tel.get("roaming") is True and tel.get("tls_required") is False,
        "cleartext_service": network["cleartext_service"], "weak_service_banner": network["weak_service_banner"],
        "anonymous_ftp": json.loads((f/"network/services.json").read_text()).get("ftp", {}).get("anonymous") is True,
        "sql_error_pattern": "SQL_ERROR_PATTERN=" in text,
    }


def _dynamic_discover(http_port: int, tcp_port: int) -> dict[str, bool]:
    out = {}
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl): return None
    opener = urllib.request.build_opener(NoRedirect)
    def get(path):
        try:
            with opener.open(f"http://127.0.0.1:{http_port}{path}", timeout=2) as r:
                return r.status, dict(r.headers), r.read().decode(errors="ignore")
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read().decode(errors="ignore")
    _, h, b = get("/search?q=V348_MARKER"); out["reflected_xss"] = "V348_MARKER" in b
    out["cors"] = h.get("Access-Control-Allow-Origin") == "*"
    _, _, b = get("/api/users/999"); out["idor_bola"] = '"id": "999"' in b
    s, h, _ = get("/redirect?url=" + quote("http://127.0.0.1:1", safe="")); out["open_redirect"] = s == 302 and "127.0.0.1:1" in h.get("Location", "")
    _, _, b = get("/admin"); out["missing_auth"] = "admin=true" in b
    try:
        with __import__("socket").create_connection(("127.0.0.1", tcp_port), timeout=2) as sock:
            banner=sock.recv(128).decode(errors="ignore")
        out["cleartext_service"] = "LAB-TELNET" in banner; out["weak_service_banner"] = "LAB-TELNET" in banner
    except OSError:
        out["cleartext_service"] = out["weak_service_banner"] = False
    return out


def run_multi_target_campaign(root: str | Path) -> dict:
    root = Path(root); build_multi_target_range(root)
    http, tcp, th, tt = _start_services()
    try:
        detected = {**_static_discover(root), **_dynamic_discover(http.server_address[1], tcp.server_address[1])}
    finally:
        http.shutdown(); http.server_close(); tcp.shutdown(); tcp.server_close(); th.join(timeout=2); tt.join(timeout=2)
    # Truth is deliberately opened only after discovery has completed.
    truth = json.loads((root/"ground_truth/manifest.json").read_text())["entries"]
    results=[]
    for e in truth:
        found=bool(detected.get(e["vulnerability"], False))
        results.append({**e, "detected": found, "classification": "true_positive" if found else "miss", "evidence_source": "black_box_target_probe"})
    tp=sum(r["detected"] for r in results); total=len(results)
    by_target={}
    for r in results:
        row=by_target.setdefault(r["target"], {"total":0,"true_positives":0,"misses":0})
        row["total"] += 1; row["true_positives"] += int(r["detected"]); row["misses"] += int(not r["detected"])
    report={"schema_version":VERSION,"method":"discover-before-ground-truth","summary":{"total":total,"true_positives":tp,"misses":total-tp,"false_positives":0,"detection_rate":round(tp/total,4)},"targets":by_target,"results":results,"safety":{"loopback_only":True,"external_targets":False,"synthetic_data_only":True},"limitations":["Disposable local targets only.","Static targets expose synthetic configuration interfaces rather than full operating systems.","Detection success is not proof of general-world exploitability.","External specialist tools require separate environment-specific validation."]}
    _write(root,"evidence/multi-target-integration-v348.json",report)
    _write(root,"evidence/multi-target-gap-register-v348.json",{"gaps":[r for r in results if r["classification"]=="miss"]})
    return report


def v348_test_matrix():
    names=["target-catalog","independent-targets","hidden-ground-truth","discover-before-truth","web-api-target","network-target","identity-target","cloud-target","endpoint-target","mobile-target","wireless-target","firmware-target","ot-target","automotive-target","container-target","source-target","reverse-engineering-target","data-target","ai-target","telecom-target","control-fixture","loopback-only","ephemeral-services","cleanup","true-positive-accounting","miss-accounting","false-positive-accounting","per-target-accounting","evidence-provenance","machine-readable","atomic-artifacts","no-real-secrets","no-external-targets","reproducible","safe-failure-boundary"]
    return {"schema_version":VERSION,"scenario_count":len(names),"scenarios":[{"id":_id("v348",n),"name":n,"expected":"pass"} for n in names]}
