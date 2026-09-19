from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime,timezone

def create_lab(outdir,client='LAB',target='lab.local'):
    root=Path(outdir); ev=root/'evidence'; rep=root/'reports'; ev.mkdir(parents=True,exist_ok=True); rep.mkdir(parents=True,exist_ok=True); now=datetime.now(timezone.utc).isoformat()
    fs=[
      {'id':'LAB-F001','finding_id':'LAB-F001','label':'Authentication weakness','severity':'high','status':'confirmed','confidence':.95,'asset':'app.lab.local','surface':'web','metadata':{'evidence_quality':.9,'prerequisites':['Endpoint is in scope'],'capabilities_gained':['initial-access']}},
      {'id':'LAB-F002','finding_id':'LAB-F002','label':'Exposed administrative interface','severity':'medium','status':'unreviewed','confidence':.55,'asset':'app.lab.local','surface':'web','metadata':{'evidence_quality':.45,'prerequisites':['Admin interface reachable'],'capabilities_gained':['discovery']}},
      {'id':'LAB-F003','finding_id':'LAB-F003','label':'Over-privileged API authorization','severity':'critical','status':'candidate','confidence':.42,'asset':'api.lab.local','surface':'api','metadata':{'evidence_quality':.35,'prerequisites':['Authenticated test identity'],'capabilities_gained':['privilege-escalation']}}]
    graph={'schema_version':'lab-1.0','nodes':fs+[{'id':'A-app','type':'asset','label':'app.lab.local'},{'id':'A-api','type':'asset','label':'api.lab.local'}],'edges':[{'source':'LAB-F001','target':'LAB-F003','type':'may-enable','status':'hypothesis','confidence':.52,'rationale':'Synthetic lab relationship.'}]}
    for name,data in [('attack-graph.json',graph),('assets.json',{'assets':[{'asset_id':'A-app','host':'app.lab.local','ports':[443],'technologies':['synthetic-web']},{'asset_id':'A-api','host':'api.lab.local','ports':[443],'technologies':['synthetic-api']}]}),('evidence-index.json',{'evidence':[{'evidence_id':f'LAB-E00{i+1}','finding_id':f'LAB-F00{i+1}','type':'synthetic','description':'Synthetic only.','created_at':now} for i in range(3)]}),('timeline.json',[{'timestamp':now,'event':'lab_created','detail':'Synthetic engagement created.'}]),('engagement.json',{'schema_version':'lab-1.0','engagement_id':root.name,'client':client,'target':target,'mode':'synthetic-lab','started':now,'artifacts':{}})]: (ev/name).write_text(json.dumps(data,indent=2),encoding='utf-8')
    (rep/'lab-readme.md').write_text('# Synthetic Lab\n\nSynthetic data only; no real target is contacted.\n',encoding='utf-8'); return root
