#!/usr/bin/env python3
"""V55 bounded session-security observations using public HTTP responses only."""
from __future__ import annotations
import json, re
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse

SENSITIVE_COOKIE_RE=re.compile(r"(?i)\b(session|sid|auth|token|jwt|access|refresh)[^=]*=([^;\s]+)")

def _redact_cookie(value: str) -> str:
    return SENSITIVE_COOKIE_RE.sub(lambda m: m.group(1)+"=<REDACTED>", value)

def _allowed(url: str, scope: list[str]) -> bool:
    host=(urlparse(url).hostname or "").lower().rstrip(".")
    for rule in scope:
        r=rule.strip().lower().rstrip(".")
        if r and (host==r or host.endswith("."+r)):
            return True
    return False

def run(root: str|Path, scope_file: str|Path, approved: bool=False, max_requests: int=6, timeout: int=8):
    if not approved: raise PermissionError("V55 observations require explicit operator approval")
    root=Path(root); sf=Path(scope_file)
    if not sf.exists(): raise FileNotFoundError("scope file is required")
    scope=[x.strip() for x in sf.read_text(encoding="utf-8").splitlines() if x.strip() and not x.lstrip().startswith("#")]
    if not scope: raise PermissionError("empty scope is not allowed")
    src=root/"evidence"/"session-intelligence-v54.json"
    if not src.exists(): raise FileNotFoundError("V54 session intelligence not found; run --session-intelligence first")
    data=json.loads(src.read_text(encoding="utf-8")); urls=[]
    for s in data.get("surfaces",[]):
        u=s.get("endpoint","")
        if u.startswith(("http://","https://")) and u not in urls and _allowed(u,scope): urls.append(u)
        if len(urls)>=max_requests: break
    results=[]
    for url in urls:
        row={"url":url,"status":"blocked","redirects_followed":False,"secret_values_collected":False}
        try:
            from modules.safe_http import request as safe_request
            observed=safe_request(url, method="GET", headers={"User-Agent":"PentestAutomationFramework/V55"}, timeout=timeout)
            headers={k.lower(): _redact_cookie(v) if k.lower()=="set-cookie" else str(v)[:500] for k,v in observed.get("headers",{}).items()}
            if observed.get("ok"):
                row.update({"status":"observed","http_status":observed.get("status"),"headers":headers,
                            "set_cookie_present":"set-cookie" in headers,
                            "location_present":"location" in headers})
            else:
                row.update({"status":"error","error_type":observed.get("error","transport-error")})
        except (OSError, ValueError, TypeError) as exc:
            row.update({"status":"error","error_type":type(exc).__name__})
        results.append(row)
    out={"schema_version":"55.0","generated":datetime.now(timezone.utc).isoformat(),"approved":True,
         "max_requests":max_requests,"request_count":len(results),"redirects_followed":False,"secret_values_collected":False,
         "results":results,"human_control_required":True}
    ep=root/"evidence"/"session-observations-v55.json"; ep.parent.mkdir(parents=True,exist_ok=True); ep.write_text(json.dumps(out,indent=2),encoding="utf-8")
    rp=root/"reports"/"session-observations-v55.md"; rp.parent.mkdir(parents=True,exist_ok=True)
    lines=["# Session Security Observations (V55)",""," > Bounded GET observations only. Redirects are not followed and sensitive cookie values are redacted.",""]
    for r in results: lines.append(f"- `{r['url']}` — **{r['status']}**" + (f" HTTP {r['http_status']}" if 'http_status' in r else ""))
    rp.write_text("\n".join(lines)+"\n",encoding="utf-8")
    return ep,rp
