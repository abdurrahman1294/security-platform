from __future__ import annotations
import ast, hashlib, json, os, re
from datetime import datetime, timezone
from pathlib import Path
from .hardening_v161_v175 import atomic_write_json

FORBIDDEN_PATTERNS = {
    "shell_true": re.compile(r"shell\s*=\s*True"),
    "os_system": re.compile(r"\bos\.system\s*\("),
    "os_popen": re.compile(r"\bos\.popen\s*\("),
}

class AuditVisitor(ast.NodeVisitor):
    def __init__(self): self.issues=[]
    def visit_Call(self,node):
        try:
            if isinstance(node.func,ast.Attribute) and node.func.attr in {"system","popen"} and isinstance(node.func.value,ast.Name) and node.func.value.id=="os":
                self.issues.append((node.lineno,f"os.{node.func.attr}"))
            for kw in node.keywords:
                if kw.arg=="shell" and isinstance(kw.value,ast.Constant) and kw.value.value is True:
                    self.issues.append((node.lineno,"shell=True"))
        finally: self.generic_visit(node)

def audit_source_tree(root):
    root=Path(root); findings=[]
    for p in sorted(root.rglob("*.py")):
        if any(part in {".git",".pytest_cache"} for part in p.parts): continue
        try: tree=ast.parse(p.read_text(encoding="utf-8"),filename=str(p))
        except (OSError, UnicodeError, SyntaxError) as exc:
            findings.append({"file":str(p.relative_to(root)),"severity":"error","issue":"parse-error","detail":str(exc)[:200]}); continue
        v=AuditVisitor(); v.visit(tree)
        for line,issue in v.issues:
            findings.append({"file":str(p.relative_to(root)),"line":line,"severity":"high","issue":issue})
    return findings

def build_security_audit(root):
    root=Path(root); findings=audit_source_tree(root)
    ev=root/"evidence"; ev.mkdir(parents=True,exist_ok=True)
    return atomic_write_json(ev/"security-hardening-audit-v163-v170.json", {
        "schema_version":"163-170.0","generated_at":datetime.now(timezone.utc).isoformat(),
        "policy":"Registered-tool execution, no shell=True/os.system/os.popen, explicit safety review.",
        "files_scanned":sum(1 for _ in root.rglob("*.py")),"findings":findings,
        "decision":"PASS" if not findings else "REVIEW_REQUIRED"
    })

def build_runtime_policy(root):
    return atomic_write_json(Path(root)/"evidence/runtime-hardening-policy-v164.json", {
        "schema_version":"164.0","controls":{
            "registered_tool_only":True,"shell_execution":False,"bounded_timeouts":True,
            "bounded_arguments":True,"secret_environment_filtering":True,"atomic_artifacts":True,
            "fail_closed_scope":True,"private_osint_networks_blocked":True,
            "operator_approval_for_active_testing":True,"no_hidden_agents":True,
            "no_covert_tracking":True,"no_private_account_access":True
        },
        "completion_rule":"No production-ready claim when hardening audit or quality gate requires review."
    })
