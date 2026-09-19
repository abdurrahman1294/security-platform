"""V3.5 service/protocol coverage intelligence from existing inventories."""
from __future__ import annotations
import json
from pathlib import Path
from modules.atomic_io import atomic_write_json

PORTS={21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"dns",80:"http",110:"pop3",111:"rpcbind",135:"msrpc",139:"netbios",143:"imap",389:"ldap",443:"https",445:"smb",465:"smtps",587:"smtp",636:"ldaps",993:"imaps",995:"pop3s",1433:"mssql",1521:"oracle",2049:"nfs",2375:"docker",3306:"mysql",3389:"rdp",5432:"postgresql",5900:"vnc",5985:"winrm",6379:"redis",6443:"kubernetes-api",9200:"elasticsearch",27017:"mongodb"}

def build(root: str|Path)->dict:
    root=Path(root); ev=root/"evidence"; ev.mkdir(parents=True,exist_ok=True)
    p=root/"evidence/normalized-attack-surface-v34.json"
    try: doc=json.loads(p.read_text(encoding="utf-8"))
    except (OSError,UnicodeDecodeError,json.JSONDecodeError): doc={"services":[]}
    services=doc.get("services",[]) if isinstance(doc,dict) else []
    rows=[]; seen=set()
    for s in services:
        if not isinstance(s,dict): continue
        try: port=int(s.get("port"))
        except (TypeError,ValueError): continue
        proto=str(s.get("service") or PORTS.get(port,"unknown")).lower()
        key=(str(s.get("asset") or ""),port,proto)
        if key in seen: continue
        seen.add(key)
        flags=[]
        if port in {21,23,80,110,143,139,445,2375,6379,9200,27017}: flags.append("review-cleartext-or-legacy-exposure")
        if port in {2375,6443,3389,5985,445}: flags.append("high-value-management-surface")
        rows.append({"asset":key[0],"port":port,"protocol":proto,"flags":flags,"status":"observed"})
    out={"schema_version":"3.5","status":"completed","service_count":len(rows),"services":rows,"coverage":sorted(set(x["protocol"] for x in rows))}
    atomic_write_json(ev/"service-protocol-intelligence-v35.json",out); return out
