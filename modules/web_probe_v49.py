#!/usr/bin/env python3
"""V49: bounded, approval-gated HTTP observation runner.
Only HEAD/GET/OPTIONS are supported; no redirects, mutation, payload injection, or secrets.
"""
from __future__ import annotations
import json, hashlib
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse

from modules.safe_http import request as safe_request

MAX_REQUESTS=10; MAX_BODY=65536

def _in_scope(url, scope_file):
    if not scope_file or not Path(scope_file).exists(): return False
    host=(urlparse(url).hostname or "").lower().rstrip('.')
    allowed=[]
    for line in Path(scope_file).read_text(errors="ignore").splitlines():
        s=line.strip().lower().lstrip('.').rstrip('.')
        if s and not s.startswith('#'): allowed.append(s)
    return bool(host) and any(host==a or host.endswith('.'+a) for a in allowed)

def run(root: str|Path, scope_file: str, approved: bool=False, max_requests: int=MAX_REQUESTS):
    root=Path(root); src=root/"evidence"/"web-test-matrix-v48.json"
    if not src.exists(): raise FileNotFoundError("V48 matrix not found; run --web-test-matrix first")
    if not approved: raise PermissionError("V49 execution requires explicit operator approval")
    if not scope_file: raise PermissionError("V49 requires a non-empty scope file")
    data=json.loads(src.read_text(encoding="utf-8")); results=[]; seen=set(); budget=min(MAX_REQUESTS,max(1,int(max_requests)))
    for test in data.get("tests",[]):
        url=test.get("target") or ""
        if not url.startswith(("http://","https://")) or url in seen or len(results)>=budget: continue
        seen.add(url)
        if not _in_scope(url,scope_file):
            results.append({"test_case":test["test_case"],"url":url,"status":"blocked","reason":"out-of-scope"}); continue
        obs=safe_request(url,method="GET",headers={"User-Agent":"PentestAutomationFramework/49"},timeout=5,max_body=MAX_BODY)
        if not obs.get("ok"):
            results.append({"test_case":test["test_case"],"url":url,"status":"error","error":obs.get("error","RequestFailed")}); continue
        body=obs.get("body","").encode("utf-8","replace")
        headers={k.lower():v for k,v in (obs.get("headers") or {}).items()}
        row={"test_case":test["test_case"],"url":url,"status":"observed","http_status":obs.get("status"),
             "content_type":headers.get("content-type",""),"security_headers":{k:headers.get(k,"") for k in ("content-security-policy","strict-transport-security","x-content-type-options","x-frame-options","referrer-policy")},
             "body_bytes":len(body),"body_sha256":hashlib.sha256(body).hexdigest(),"redirects_followed":False}
        if obs.get("location"):
            # A 3xx was returned; it was recorded but never fetched. The
            # Location target has NOT been scope-checked or requested.
            row["location"]=obs["location"]
            row["note"]="Server returned a redirect; it was not followed."
        results.append(row)
    out={"schema_version":"49.0","generated":datetime.now(timezone.utc).isoformat(),"approved":True,"request_budget":budget,"result_count":len(results),"results":results}
    ep=root/"evidence"/"web-probe-v49.json"; ep.write_text(json.dumps(out,indent=2),encoding="utf-8")
    rp=root/"reports"/"web-probe-v49.md"; rp.write_text("# Bounded Web/API Observation (V49)\n\n> GET-only, scope-checked, non-destructive observations. No redirects or payload injection.\n\n"+"\n".join(f"- `{r['test_case']}` — **{r['status']}** — `{r['url']}`" for r in results)+"\n",encoding="utf-8")
    return ep,rp
