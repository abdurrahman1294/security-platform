"""V3.52 canonical evidence normalization for approved specialist tools.

Parses bounded, already-collected tool output into a common evidence shape.
This module never executes a command and never turns parsed scanner output into
an exploit/compromise claim by itself.
"""
from __future__ import annotations
from pathlib import Path
import hashlib, json, re, time, xml.etree.ElementTree as ET
from modules.reliability_execution_integrity_v331 import atomic_write, redact

VERSION = "3.52.0"


def _id(*p):
    return hashlib.sha256("|".join(map(str, p)).encode()).hexdigest()[:20]


def _ev(tool, kind, subject, data, *, confidence="observed"):
    return {"evidence_id": _id("v352", tool, kind, subject, json.dumps(data, sort_keys=True)), "tool": tool, "kind": kind, "subject": subject, "confidence": confidence, "data": data, "created_at": time.time()}


def parse_nmap_xml(text: str) -> list[dict]:
    out=[]
    try: root=ET.fromstring(text)
    except ET.ParseError: return out
    for host in root.findall("host"):
        addr=host.find("address")
        subject=addr.get("addr") if addr is not None else "unknown"
        for port in host.findall("./ports/port"):
            state=port.find("state"); service=port.find("service")
            if state is None or state.get("state") != "open": continue
            data={"port":int(port.get("portid","0")),"protocol":port.get("protocol",""),"state":state.get("state",""),"service":service.get("name","") if service is not None else "","product":service.get("product","") if service is not None else "","version":service.get("version","") if service is not None else ""}
            out.append(_ev("nmap","open-service",subject,data))
    return out


def parse_jsonl(text: str, tool: str) -> list[dict]:
    out=[]
    for line in text.splitlines():
        line=line.strip()
        if not line: continue
        try: obj=json.loads(line)
        except json.JSONDecodeError: continue
        if tool == "httpx":
            subject=obj.get("url") or obj.get("input") or obj.get("host") or "unknown"
            out.append(_ev(tool,"http-observation",subject,{k:obj[k] for k in ("url","status_code","title","webserver","host","port","tech") if k in obj}))
        elif tool == "nuclei":
            subject=obj.get("matched-at") or obj.get("host") or obj.get("url") or "unknown"
            out.append(_ev(tool,"scanner-finding-candidate",subject,{k:obj[k] for k in ("template-id","info","matched-at","type","host") if k in obj},confidence="candidate"))
        else:
            out.append(_ev(tool,"json-observation",str(obj.get("host") or obj.get("url") or "unknown"),obj))
    return out


def parse_lines(text: str, tool: str) -> list[dict]:
    out=[]
    for line in text.splitlines():
        s=line.strip()
        if not s: continue
        if tool == "naabu" and re.fullmatch(r"[^:]+:\d+", s):
            host,port=s.rsplit(":",1); out.append(_ev(tool,"open-port",host,{"port":int(port)}))
        elif tool == "katana":
            out.append(_ev(tool,"url-observation",s,{"url":s}))
        elif tool == "nxc":
            out.append(_ev(tool,"identity-or-service-observation",s,{"line":s}))
    return out


def parse_tool_output(tool: str, text: str, *, format: str = "auto") -> list[dict]:
    if format == "nmap-xml" or (format == "auto" and tool == "nmap" and text.lstrip().startswith("<?xml")):
        return parse_nmap_xml(text)
    if format in {"jsonl", "auto"} and tool in {"httpx","nuclei"}:
        return parse_jsonl(text, tool)
    return parse_lines(text, tool)


def normalize_files(root: str | Path, inputs: list[dict]) -> dict:
    root=Path(root); root.mkdir(parents=True, exist_ok=True)
    all_ev=[]; errors=[]
    for item in inputs:
        tool=str(item.get("tool","")); path=Path(item.get("path",""))
        try:
            path=path.resolve(); path.relative_to(root.resolve())
            text=path.read_text(errors="replace")
            all_ev.extend(parse_tool_output(tool,text,format=str(item.get("format","auto"))))
        except Exception as exc:
            errors.append({"tool":tool,"error_type":type(exc).__name__})
    report={"schema_version":VERSION,"status":"PASS" if not errors else "PARTIAL","evidence_count":len(all_ev),"errors":errors,"evidence":all_ev,"claim_boundary":"Parsed evidence does not self-upgrade to validated compromise."}
    atomic_write(root/"evidence/tool-evidence-normalization-v352.json", redact(report))
    return report


def v352_test_matrix():
    names=["nmap-xml","httpx-jsonl","nuclei-candidate","naabu-lines","katana-lines","nxc-lines","canonical-id","provenance","candidate-boundary","path-sandbox","parse-error-isolation","machine-readable","atomic-artifact","redaction","no-execution","no-command-synthesis","deterministic-shape","empty-input","unknown-lines-safe","tool-label-preserved"]
    return {"schema_version":VERSION,"scenario_count":len(names),"scenarios":[{"id":_id("v352-test",n),"name":n,"expected":"pass"} for n in names]}
