#!/usr/bin/env python3
"""Twenty-pass pre-active-test regression gate for the security platform.
Each pass targets a known defect class uncovered during review and verifies its
correction. All checks are local/static; no external target is contacted.
"""
from __future__ import annotations
import ast, importlib, json, subprocess, sys, tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

checks=[]
def check(name, fn):
    try:
        fn(); checks.append((name,"PASS",""))
    except Exception as e:
        checks.append((name,"FAIL",f"{type(e).__name__}: {e}"))

def p1():
    from modules.lab_http import base
    for u in ["http://127.0.0.1:8080/?x=1","http://user@127.0.0.1:8080","http://127.0.0.1:8080/#x","http://127.0.0.1:8080/path"]:
        try: base(u)
        except ValueError: continue
        raise AssertionError(u)

def p2():
    from modules.lab_http import request
    r=request("http://127.0.0.1:1",method="PUT")
    assert r["error"]=="method-not-allowed"

def p3():
    from modules.lab_http import request
    r=request("http://127.0.0.1:1",method="GET",max_body=10**20,timeout=10**20)
    assert r.get("ok") is False and r.get("error")

def p4():
    from modules.controlled_validation_v21 import validate
    try: validate(Path(tempfile.mkdtemp()),"https://example.com")
    except ValueError: return
    raise AssertionError("remote target accepted")

def p5():
    from modules.persistence_lab_v21 import run
    assert run(tempfile.mkdtemp(),"http://127.0.0.10:8080")["status"]=="blocked"

def p6():
    from modules.lateral_movement_lab_v21 import run
    assert run(tempfile.mkdtemp(),"http://127.0.0.1:8080","http://127.0.0.10:8082")["status"]=="blocked"

def p7():
    from modules.lateral_movement_lab_v21 import run
    assert run(tempfile.mkdtemp(),"http://127.0.0.1:8080","http://127.0.0.1:8080")["status"]=="blocked"

def p8():
    from modules.exploitation_catalog_v22 import CATALOG
    assert len(CATALOG)>=20

def p9():
    from modules.exploitation_catalog_v22 import validate
    try: validate(tempfile.mkdtemp(),"http://127.0.0.1:8080",["unknown"])
    except ValueError: return
    raise AssertionError("unknown capability accepted")

def p10():
    from modules.evidence_reasoner_v21 import reason
    root=Path(tempfile.mkdtemp()); (root/"evidence").mkdir()
    (root/"evidence"/"exploitation-catalog-v22.json").write_text(json.dumps({"results":[{"capability":"ssrf","status":"CONFIRMED"}]}))
    out=reason(root)
    assert any(d["trigger"]=="ssrf" for d in out["decisions"])

def p11():
    from modules.attack_chain_lab_v20 import run_lab_attack_chain
    root=Path(tempfile.mkdtemp()); out=run_lab_attack_chain(root,authorized=False)
    assert (root/"evidence"/"attack-chain-final.json").is_file() and out["status"]=="blocked"

def p12():
    from modules.attack_chain_lab_v20 import run_lab_attack_chain
    root=Path(tempfile.mkdtemp()); out=run_lab_attack_chain(root,authorized=True,execute=False)
    assert out["status"]=="dry_run" and (root/"evidence"/"attack-chain-final.json").is_file()

def p13():
    from modules.persistence_lab_v21 import run
    out=run(tempfile.mkdtemp(),"http://127.0.0.1:1",["bad"])
    assert out["results"][0]["status"]=="BLOCKED"

def p14():
    from modules.roe_policy_v18 import ROEPolicy
    r=ROEPolicy.from_dict({"enable_r4":True,"allowed_r4_actions":["controlled_attack_chain_test"],"max_impact":"high","fake_data_only":True,"production_change_allowed":False,"third_party_assets_allowed":False,"time_window":"local-lab","emergency_stop":False,"operator":"x","engagement_reference":"y","target":"http://127.0.0.1:8080"})
    assert r.permits("controlled_attack_chain_test",target="http://127.0.0.1:8080")
    assert not r.permits("controlled_attack_chain_test",target="http://127.0.0.1:8082")

def p15():
    from modules.autonomy_policy import AutonomyPolicy, RiskClass
    a=AutonomyPolicy(profile="assess")
    assert a.risk_for("unrestricted_rce")==RiskClass.R5

def p16():
    from modules.task_prioritizer import prioritize
    root=Path(tempfile.mkdtemp()); (root/"vulns").mkdir()
    (root/"vulns"/"findings.json").write_text(json.dumps([None, "bad", {"info":{"severity":"high","name":"ok"}}]))
    out=prioritize(root,"target")
    assert any(x.action=="controlled_validation" for x in out)

def p17():
    from modules.approval_queue import ApprovalQueue
    root=Path(tempfile.mkdtemp()); q=ApprovalQueue(root)
    req=q.submit("controlled_attack_chain_test","http://127.0.0.1:8080","r",risk="R4")
    token=q.approve(req.request_id); assert token
    assert q.consume(token,"controlled_attack_chain_test","http://127.0.0.1:8080")
    assert not q.consume(token,"controlled_attack_chain_test","http://127.0.0.1:8080")

def p18():
    # AST guard: no newly added lab modules may call unrestricted shell APIs.
    for f in [ROOT/"modules"/"exploitation_catalog_v22.py",ROOT/"modules"/"lab_http.py",ROOT/"modules"/"attack_chain_lab_v20.py"]:
        t=ast.parse(f.read_text())
        for n in ast.walk(t):
            if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id in {"system","popen","exec"}:
                raise AssertionError(f"unsafe call {n.func.id} in {f.name}")

def p19():
    rc=subprocess.run([sys.executable,"securityctl.py","engines"],cwd=ROOT,text=True,capture_output=True,timeout=20)
    assert rc.returncode==0 and "pentest" in rc.stdout.lower()

def p20():
    for py in ROOT.rglob("*.py"):
        ast.parse(py.read_text(encoding="utf-8"))

for i,fn in enumerate([p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12,p13,p14,p15,p16,p17,p18,p19,p20],1):
    check(f"PASS-{i:02d}",fn)

for name,status,detail in checks:
    print(f"{name} {status}" + (f" — {detail}" if detail else ""))
failed=[x for x in checks if x[1]!="PASS"]
print(f"SUMMARY passed={len(checks)-len(failed)} failed={len(failed)} total={len(checks)}")
sys.exit(1 if failed else 0)
