"""V3.67 persistent conversational security workspace."""
from __future__ import annotations
import json,time,uuid
from pathlib import Path
from typing import Any
from modules.cyber_advisor_v366 import advise
from modules.rare_case_reasoner_v367 import reason
from modules.attack_path_intelligence_v367 import build_attack_path

VERSION="3.67.0"
class SecurityConversation:
    def __init__(self,root:str|Path,target:str="",engagement:str=""):
        self.root=Path(root); self.target=target; self.engagement=engagement
        self.root.mkdir(parents=True,exist_ok=True); (self.root/"evidence").mkdir(exist_ok=True)
        self.path=self.root/"evidence"/"security-conversation-v367.json"
        self.state=self._load()
    def _load(self):
        if self.path.exists():
            try:return json.loads(self.path.read_text(encoding="utf-8"))
            except Exception:pass
        return {"schema_version":VERSION,"conversation_id":str(uuid.uuid4()),"created_at":time.time(),"messages":[]}
    def save(self): self.state["updated_at"]=time.time(); self.path.write_text(json.dumps(self.state,indent=2,ensure_ascii=False),encoding="utf-8")
    def ask(self,message:str,*,story:str="",evidence=None,findings=None)->dict[str,Any]:
        if not message.strip(): raise ValueError("message is required")
        ctx={"target":self.target,"engagement":self.engagement}
        r=advise(question=message,target=self.target,engagement=self.engagement,root=str(self.root))
        result=r["result"]
        self.state["messages"].append({"role":"user","content":message,"at":time.time()})
        self.state["messages"].append({"role":"assistant","content":result,"at":time.time()})
        self.save(); return result
    def investigate_rare(self,problem:str,*,story:str="",evidence=None):
        return reason(root=self.root,problem=problem,story=story,evidence=evidence or [])
    def attack_path(self,*,story:str="",findings=None,observations=None,prior_events=None):
        out=build_attack_path(target=self.target,story=story,findings=findings or [],observations=observations or [],prior_events=prior_events or [])
        (self.root/"evidence"/"security-attack-path-v367.json").write_text(json.dumps(out,indent=2),encoding="utf-8"); return out
