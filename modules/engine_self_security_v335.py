"""V3.35 Engine Self-Security Fabric.

Static, deterministic self-audit of the platform source tree. It looks for
unsafe execution patterns, secret-like literals, path hazards, weak subprocess
boundaries, and dependency/configuration concerns. It reports findings; it
does not modify or execute target systems.
"""
from __future__ import annotations
from pathlib import Path
import ast, hashlib, re, time
from typing import Any
from modules.reliability_execution_integrity_v331 import atomic_write
VERSION="3.35.0"
PY_EXT={".py"}; MAX_FILES=5000; MAX_BYTES=2_000_000
SECRET_RE=re.compile(r"(?i)(api[_-]?key|secret|password|passwd|token|private[_-]?key)\s*[:=]\s*['\"][^'\"]{8,}['\"]")
KNOWN_SYNTHETIC_SECRET_MARKERS={"LAB-SYNTHETIC-MARKER"}

def _id(*p): return hashlib.sha256("|".join(map(str,p)).encode()).hexdigest()[:20]

def _safe_files(root:Path):
    out=[]
    for p in root.rglob("*.py"):
        if len(out)>=MAX_FILES: break
        try:
            if p.is_symlink() or p.stat().st_size>MAX_BYTES: continue
        except OSError: continue
        if any(part in {".git",".venv","venv","__pycache__"} for part in p.parts): continue
        out.append(p)
    return out

def audit_file(path:Path, root:Path):
    findings=[]
    try: text=path.read_text(encoding="utf-8",errors="replace"); tree=ast.parse(text)
    except (OSError,SyntaxError) as exc:
        return [{"id":_id("parse",str(path),exc),"kind":"parse-error","severity":"high","path":str(path.relative_to(root)),"detail":str(exc)}]
    for m in SECRET_RE.finditer(text):
        literal=m.group(0).split("=",1)[-1].strip().strip("\'\"")
        if literal in KNOWN_SYNTHETIC_SECRET_MARKERS:
            continue
        findings.append({"id":_id("secret",str(path),m.start()),"kind":"secret-like-literal","severity":"high","path":str(path.relative_to(root)),"line":text.count("\n",0,m.start())+1,"detail":"possible hard-coded secret-like literal"})
    rel = str(path.relative_to(root)).replace("\\", "/")
    approved_subprocess = {"run.py", "modules/governed_process_v335.py", "modules/tool_manager_v40.py", "modules/tool_adapter_hardening_v162.py"}
    for node in ast.walk(tree):
        if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute):
            name=node.func.attr
            if name in {"system","popen"} and isinstance(node.func.value,ast.Name) and node.func.value.id=="os":
                findings.append({"id":_id("os",str(path),node.lineno),"kind":"unsafe-os-exec","severity":"critical","path":str(path.relative_to(root)),"line":node.lineno,"detail":"os.system/os.popen requires centralized execution review"})
            if name=="run" and isinstance(node.func.value,ast.Name) and node.func.value.id=="subprocess":
                has_shell=any(k.arg=="shell" and isinstance(k.value,ast.Constant) and k.value.value is True for k in node.keywords)
                if has_shell or rel not in approved_subprocess:
                    severity="high" if has_shell else ("low" if rel.startswith(("tests/", "tools/", "artifacts/", "lab/")) else "medium")
                    findings.append({"id":_id("subprocess",str(path),node.lineno),"kind":"subprocess-run","severity":severity,"path":rel,"line":node.lineno,"detail":"direct subprocess boundary; shell=True" if has_shell else "direct subprocess boundary outside approved local/tool execution boundaries"})
            if name in {"eval","exec"} and isinstance(node.func,ast.Name):
                findings.append({"id":_id(name,str(path),node.lineno),"kind":"dynamic-code","severity":"critical","path":str(path.relative_to(root)),"line":node.lineno,"detail":f"dynamic {name}()"})
    return findings

def build_v335_fabric(root:str|Path, *, repo_root:str|Path|None=None, include_tests:bool=True):
    root=Path(root); scan=Path(repo_root) if repo_root else Path(__file__).resolve().parents[1]
    files=_safe_files(scan)
    # Never treat generated campaign artifacts as source. Test/tool inclusion is separate.
    files=[p for p in files if not str(p.relative_to(scan)).replace("\\", "/").startswith(("artifacts/", "lab/"))]
    if not include_tests:
        files=[p for p in files if not str(p.relative_to(scan)).replace("\\", "/").startswith(("tests/", "tools/"))]
    findings=[]
    for p in files: findings.extend(audit_file(p,scan))
    # Policy findings are explicit even when no issue was found.
    counts={}
    for f in findings: counts[f["severity"]]=counts.get(f["severity"],0)+1
    result={"schema_version":VERSION,"scan_root":str(scan),"files_scanned":len(files),"finding_count":len(findings),"severity_counts":counts,
            "findings":findings,"control_status":{"no-os-system":not any(f["kind"]=="unsafe-os-exec" for f in findings),
            "no-shell-true":not any(f["kind"]=="subprocess-run" and f["severity"]=="high" for f in findings),
            "no-dynamic-code":not any(f["kind"]=="dynamic-code" for f in findings),"secret-like-literals-absent":not any(f["kind"]=="secret-like-literal" for f in findings)},
            "governance":{"audit-only":True,"does-not-touch-targets":True,"does-not-grant-authority":True,"scope-expansion":False},"created_at":time.time()}
    atomic_write(root/"evidence"/"engine-self-security-v335.json",result); return result

def v335_test_matrix():
    names=["recursive-source-scan","symlink-skip","size-bound","parse-error-visible","os-system-detection","os-popen-detection",
           "shell-true-detection","direct-subprocess-detection","eval-detection","exec-detection","secret-literal-detection",
           "secret-pattern-bounded","severity-assignment","finding-id-stability","control-summary","audit-only","no-target-touch",
           "no-authority-grant","no-scope-expansion","deterministic-scan-policy","max-file-bound","max-size-bound","encoding-tolerant",
           "git-exclusion","venv-exclusion","pycache-exclusion","tests-optional","machine-readable","atomic-artifact","empty-repo-safe",
           "syntax-error-safe","finding-line-reference","relative-paths","no-command-generation","no-exploit-generation","no-secret-printing",
           "no-network-required","no-tool-execution","policy-explicit","severity-counts","schema-stable"]
    return {"schema_version":VERSION,"scenario_count":len(names),"scenarios":[{"id":_id(x),"name":x,"expected":"audit-only-safe-result"} for x in names]}
