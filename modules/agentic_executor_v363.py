"""V3.63 governed agent executor.

Bridges model-selected actions to the existing ToolManager. The LLM never gets
an implicit shell: every action is a structured call to a registered tool,
checked again immediately before execution. Results are fed back to the next
reasoning turn, enabling adaptive exploitation rather than a fixed Python
playbook.
"""
from __future__ import annotations
import hashlib, json, time
from pathlib import Path
from typing import Any, Iterable

from security_platform.core.tools import run
from modules.tool_manager_v40 import TOOLS

VERSION = "3.63.0"


def _id(*x: Any) -> str:
    return hashlib.sha256("|".join(map(str, x)).encode()).hexdigest()[:20]


def execute_actions(root: str | Path, actions: Iterable[dict[str, Any]], *,
                    target: str, in_scope, authorized: bool,
                    approval_token: str = "", max_actions: int = 4,
                    timeout: int = 900) -> dict[str, Any]:
    """Execute only already-validated structured tool actions."""
    root = Path(root); evidence = root / "evidence"; evidence.mkdir(parents=True, exist_ok=True)
    receipts=[]
    for raw in list(actions)[:max_actions]:
        tool=str(raw.get("tool", "")); action_target=str(raw.get("target", ""))
        args=raw.get("args", [])
        risk=str(raw.get("risk", "medium")).lower()
        approval=bool(raw.get("requires_approval", False)) or risk in {"high","critical"}
        receipt={"action_id":raw.get("action_id") or _id(tool,action_target,args),"tool":tool,
                 "target":action_target,"started_at":time.time(),"status":"rejected"}
        if not authorized:
            receipt["reason"]="authorization-required"; receipts.append(receipt); continue
        if not in_scope(action_target):
            receipt["reason"]="out-of-scope"; receipts.append(receipt); continue
        if tool not in TOOLS:
            receipt["reason"]="unregistered-tool"; receipts.append(receipt); continue
        if approval and not approval_token:
            receipt["reason"]="approval-required"; receipts.append(receipt); continue
        if not isinstance(args, (list,tuple)) or any(not isinstance(x,str) for x in args):
            receipt["reason"]="invalid-args"; receipts.append(receipt); continue
        # Never invoke a shell. ToolManager receives argv as a list.
        argv=[tool,*args]
        try:
            result=run(root, tool, argv, timeout=timeout)
            receipt.update({"status":"completed" if result.returncode == 0 else "failed",
                            "returncode":result.returncode,
                            "stdout":(result.stdout or "")[-12000:],
                            "stderr":(result.stderr or "")[-6000:]})
        except Exception as exc:
            receipt.update({"status":"error","error":f"{type(exc).__name__}:{str(exc)[:500]}"})
        receipt["finished_at"]=time.time(); receipts.append(receipt)
    out={"schema_version":VERSION,"target":target,"receipts":receipts,
         "governance":{"structured_argv_only":True,"registered_tools_only":True,
                        "scope_rechecked":True,"authorization_rechecked":True,
                        "shell_interpretation":False}}
    (evidence/"agent-execution-v363.json").write_text(json.dumps(out,indent=2),encoding="utf-8")
    return out
