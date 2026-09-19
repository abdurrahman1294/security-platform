from __future__ import annotations
import logging
logger = logging.getLogger(__name__)
import json, re, shutil, zipfile
from pathlib import Path
from xml.etree import ElementTree as ET
from modules.atomic_io import atomic_write_json
from modules.governed_process_v335 import run_fixed
from modules.security import redact_mapping

VERSION = "23.0"
ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
SENSITIVE_PERMS = {
    "android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS", "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO", "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE", "android.permission.REQUEST_INSTALL_PACKAGES",
}


def _run(cmd, timeout=60):
    if not cmd:
        return {"returncode": None, "stdout": "", "stderr": "empty-argv"}
    return run_fixed(Path(cmd[0]).name, cmd, timeout=timeout)


def _tool(name):
    return shutil.which(name)


def _aapt_manifest(apk: Path):
    for tool in ("apkanalyzer", "aapt2", "aapt"):
        path = _tool(tool)
        if not path:
            continue
        args = [path, "manifest", "print", str(apk)] if tool == "apkanalyzer" else [path, "dump", "xmltree", str(apk), "AndroidManifest.xml"]
        result = _run(args)
        if result["returncode"] == 0 and result["stdout"]:
            return tool, result["stdout"]
    return None, ""


def _text_manifest(zf):
    try:
        raw = zf.read("AndroidManifest.xml")
        text = raw.decode("utf-8", errors="ignore")
        if "<manifest" in text:
            return text
    except KeyError:
        pass
    return ""


def _find_strings(blob: bytes):
    text = blob.decode("utf-8", errors="ignore")
    urls = sorted(set(re.findall(r"https?://[^\s\"'<>]{4,200}", text)))[:100]
    secrets = []
    patterns = [
        r"(?i)(api[_-]?key|secret|token|password)\s*[=:]\s*[A-Za-z0-9_\-./+=]{8,}",
        r"AKIA[0-9A-Z]{16}",
    ]
    for pat in patterns:
        secrets.extend(re.findall(pat, text))
    return urls, sorted(set(secrets))[:50]


def _heuristics(blob: bytes, names):
    text = blob.decode("utf-8", errors="ignore")
    checks = []
    def add(cid, title, severity, evidence, remediation):
        checks.append({"id": cid, "title": title, "severity": severity, "evidence": evidence, "remediation": remediation})
    if b"android:debuggable=\"true\"" in blob or b"debuggable=true" in blob:
        add("AND-DBG", "Debuggable application", "high", "debuggable=true marker observed", "Disable debugging in release builds.")
    if b"usesCleartextTraffic=\"true\"" in blob or b"usesCleartextTraffic=true" in blob:
        add("AND-CLEAR", "Cleartext traffic permitted", "medium", "usesCleartextTraffic=true marker observed", "Require TLS and disable cleartext traffic where not explicitly required.")
    if b"android:allowBackup=\"true\"" in blob:
        add("AND-BACKUP", "Application backup enabled", "medium", "allowBackup=true marker observed", "Review backup policy and exclude sensitive application data.")
    if b"WebView" in blob and (b"setJavaScriptEnabled" in blob or b"addJavascriptInterface" in blob):
        add("AND-WEBVIEW", "WebView JavaScript/interface surface", "medium", "WebView JavaScript/interface indicators found", "Review trusted-content boundaries and JavaScript interfaces.")
    if b"http://" in blob:
        add("AND-HTTP", "HTTP URL reference", "medium", "http:// reference found in application bytes", "Use HTTPS for sensitive communication and validate endpoints.")
    if b"DES/ECB" in blob or b"MD5" in blob or b"SHA-1" in blob:
        add("AND-CRYPTO", "Potential legacy cryptography", "medium", "legacy algorithm marker found", "Review cryptographic usage and migrate to modern primitives.")
    if any(n.startswith("lib/") and n.endswith((".so", ".elf")) for n in names):
        add("AND-NATIVE", "Native code present", "info", "Native libraries are packaged", "Perform native-code review and memory-safety assessment where applicable.")
    return checks


def analyze_apk(root, apk_path, *, run_tools=True):
    root = Path(root); apk = Path(apk_path)
    ev = root / "evidence"; ev.mkdir(parents=True, exist_ok=True)
    if not apk.is_file() or apk.suffix.lower() != ".apk":
        return {"status": "blocked", "reason": "apk-file-required"}
    try:
        with zipfile.ZipFile(apk) as zf:
            names = zf.namelist()
            info = zf.infolist()
            blob_parts = []
            for name in names:
                if name.endswith((".dex", ".xml", ".json", ".properties", ".txt", ".js", ".so")):
                    try: blob_parts.append(zf.read(name)[:2_000_000])
                    except Exception as exc: logger.debug("malformed archive member skipped: %s", exc)
            blob = b"\n".join(blob_parts)[:20_000_000]
            manifest = _text_manifest(zf)
    except (OSError, zipfile.BadZipFile) as exc:
        return {"status": "blocked", "reason": f"invalid-apk:{exc}"}
    tool, manifest_dump = _aapt_manifest(apk) if run_tools else (None, "")
    manifest_text = manifest or manifest_dump
    package_name = ""
    min_sdk = target_sdk = None
    permissions = []
    components = []
    if manifest:
        try:
            rootxml = ET.fromstring(manifest)
            package_name = rootxml.attrib.get("package", "")
            uses = rootxml.find("uses-sdk")
            if uses is not None:
                min_sdk = uses.attrib.get(ANDROID_NS+"minSdkVersion")
                target_sdk = uses.attrib.get(ANDROID_NS+"targetSdkVersion")
            for node in rootxml.findall("uses-permission"):
                p = node.attrib.get(ANDROID_NS+"name")
                if p: permissions.append(p)
            app = rootxml.find("application")
            if app is not None:
                for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
                    for node in app.findall(tag):
                        name = node.attrib.get(ANDROID_NS+"name", "")
                        exported = node.attrib.get(ANDROID_NS+"exported")
                        components.append({"type": tag, "name": name, "exported": exported})
        except ET.ParseError:
            pass
    # Binary-manifest fallback: retain evidence without pretending exact XML parsing succeeded.
    dump_text = manifest_dump + blob.decode("utf-8", errors="ignore")
    if not package_name:
        m = re.search(r"(?:package(?:name)?|package):?\s*=?\s*[\"']?([A-Za-z0-9_.]+)", manifest_dump, re.I)
        if m: package_name = m.group(1)
    if not permissions:
        permissions = sorted(set(re.findall(r"android\.permission\.[A-Z0-9_]+", dump_text)))[:200]
    if not components:
        for m in re.finditer(r"(?:activity|service|receiver|provider)[^\n]{0,240}(?:name|Name)[:=]\s*[\"']?([^\s,\"']+)", manifest_dump, re.I):
            components.append({"type":"manifest-component","name":m.group(1),"exported":None})
    urls, secret_markers = _find_strings(blob)
    findings = _heuristics(blob, names)
    for perm in sorted(set(permissions)):
        if perm in SENSITIVE_PERMS:
            findings.append({"id": "AND-PERM", "title": "Sensitive permission requested", "severity": "medium", "evidence": perm, "remediation": "Verify the permission is necessary and minimize access."})
    for c in components:
        if c.get("exported") == "true":
            findings.append({"id": "AND-EXP", "title": "Exported component", "severity": "medium", "evidence": c, "remediation": "Review exported components and enforce explicit permissions/intent validation."})
    result = {
        "schema_version": VERSION, "status": "completed", "apk": str(apk), "package": package_name,
        "min_sdk": min_sdk, "target_sdk": target_sdk, "permissions": sorted(set(permissions)),
        "components": components, "urls": urls, "secret_marker_count": len(secret_markers),
        "findings": findings, "tool": tool or "fallback-static-parser",
        "artifact_counts": {"files": len(names), "classes_dex": sum(n.endswith(".dex") for n in names), "native_libs": sum(n.endswith(".so") for n in names)},
        "limitations": ["Binary AndroidManifest.xml may require aapt/apkanalyzer for exact component attributes.", "Static analysis does not prove runtime exploitability.", "Secret markers are redacted and exact values are never emitted."],
    }
    atomic_write_json(ev / "android-static-v23.json", redact_mapping(result))
    return result


def dynamic_readonly(root, *, serial="", allow_physical=False):
    root = Path(root); ev=root/"evidence"; ev.mkdir(parents=True,exist_ok=True)
    adb=_tool("adb")
    if not adb: return {"status":"blocked","reason":"adb-not-installed"}
    devices=_run([adb,"devices","-l"])
    rows=[x.split()[0] for x in devices["stdout"].splitlines()[1:] if x.strip() and not x.startswith("*") and "\tdevice" in x]
    serial=serial or (rows[0] if len(rows)==1 else "")
    if not serial: return {"status":"blocked","reason":"explicit-adb-serial-required","devices":rows}
    if not allow_physical and not serial.startswith("emulator-"):
        return {"status":"blocked","reason":"physical-device-requires-explicit-allow","serial":serial}
    commands=[
        [adb,"-s",serial,"shell","getprop"],
        [adb,"-s",serial,"shell","pm","list","packages","-3"],
        [adb,"-s",serial,"shell","dumpsys","package"],
    ]
    results=[]
    for cmd in commands:
        r=_run(cmd,timeout=45); results.append({"command":" ".join(cmd[3:]),"returncode":r["returncode"],"stdout":r["stdout"][:100000]})
    out={"schema_version":VERSION,"status":"completed","serial":serial,"mode":"readonly","results":results,"limitations":["Read-only device inspection; no app modification, rooting, credential extraction, or bypass operations."]}
    atomic_write_json(ev/"android-dynamic-readonly-v23.json",redact_mapping(out)); return out
