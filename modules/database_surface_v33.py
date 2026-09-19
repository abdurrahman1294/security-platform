"""Offline database exposure analysis from normalized service inventory."""
from __future__ import annotations
import json
from pathlib import Path
from modules.atomic_io import atomic_write_json
DB_PORTS={3306:'mysql',5432:'postgresql',1433:'mssql',1521:'oracle',27017:'mongodb',6379:'redis',9200:'elasticsearch',5984:'couchdb',9042:'cassandra'}

def assess(root: str|Path, source: str|Path)->dict:
    root=Path(root); ev=root/'evidence'; ev.mkdir(parents=True,exist_ok=True); p=Path(source)
    try: doc=json.loads(p.read_text(encoding='utf-8'))
    except Exception as exc: return {'status':'blocked','reason':f'invalid-service-export:{exc}'}
    rows=doc if isinstance(doc,list) else doc.get('services',doc.get('hosts',[])) if isinstance(doc,dict) else []
    db=[]
    for row in rows if isinstance(rows,list) else []:
        if not isinstance(row,dict): continue
        port=row.get('port');
        try: name=DB_PORTS.get(int(port),str(row.get('service','')).lower())
        except (TypeError,ValueError): name=str(row.get('service','')).lower()
        if name in DB_PORTS.values() or any(x in name for x in DB_PORTS.values()):
            db.append({'host':row.get('host') or row.get('address'),'port':port,'service':name,'tls':row.get('tls'),'exposed':row.get('exposed')})
    findings=[]
    for x in db:
        if x.get('tls') is False: findings.append({'id':'DB-CLEARTEXT','title':'Database service marked as non-TLS','severity':'medium','service':x})
        if x.get('exposed') is True: findings.append({'id':'DB-EXPOSED','title':'Database service marked externally exposed','severity':'high','service':x})
    out={'schema_version':'3.3','status':'completed','database_services':db,'findings':findings,'limitations':['Exposure flags are based on supplied inventory and do not prove Internet reachability or exploitability.']}
    atomic_write_json(ev/'database-surface-v33.json',out); return out
