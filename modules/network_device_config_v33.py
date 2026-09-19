"""Offline network-device configuration review with secret-safe evidence."""
from __future__ import annotations
import re
from pathlib import Path
from modules.atomic_io import atomic_write_json

PATTERNS=[
 ('NET-TELNET',r'^\s*transport input .*telnet|^\s*telnet ', 'medium','Telnet management exposure'),
 ('NET-HTTP',r'^\s*ip http server\s*$', 'medium','HTTP management server enabled'),
 ('NET-DEFAULT-SNMP',r'(?i)snmp-server community\s+(public|private)\b', 'high','Default/common SNMP community observed'),
 ('NET-SSH-LEGACY',r'(?i)ssh.*(version 1|v1)', 'medium','Legacy SSH version indicator'),
 ('NET-AAA',r'^\s*aaa new-model\s*$', 'info','AAA framework configured'),
]
SECRET_RE=re.compile(r'(?i)(password|secret|community)\s+\S+')

def assess(root: str|Path, source: str|Path)->dict:
    root=Path(root); ev=root/'evidence'; ev.mkdir(parents=True,exist_ok=True); p=Path(source)
    try: text=p.read_text(encoding='utf-8',errors='replace')
    except OSError as exc: return {'status':'blocked','reason':str(exc)}
    findings=[]
    for cid,pat,sev,title in PATTERNS:
        if re.search(pat,text,re.M): findings.append({'id':cid,'title':title,'severity':sev})
    redacted=SECRET_RE.sub(lambda m:m.group(1)+' [REDACTED]',text)
    out={'schema_version':'3.3','status':'completed','source':str(p),'line_count':len(text.splitlines()),'findings':findings,'redacted_config':redacted[:200000], 'limitations':['Configuration review is static; management reachability and segmentation require separate authorized validation.']}
    atomic_write_json(ev/'network-device-config-v33.json',out); return out
