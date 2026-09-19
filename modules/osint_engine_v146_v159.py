from __future__ import annotations
import hashlib,json,re,ssl,urllib.request
from datetime import datetime,timezone
from pathlib import Path
SOCIAL_HOSTS=['github.com','gitlab.com','x.com','linkedin.com','facebook.com','instagram.com','youtube.com','tiktok.com','reddit.com','mastodon.social']
def _write(root,name,data):
 p=Path(root)/'evidence'/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(data,indent=2,sort_keys=True),encoding='utf-8');return p
def _get(url,timeout=8):
 r=urllib.request.Request(url,headers={'User-Agent':'SecurityOperator/OSINT passive research'})
 with urllib.request.urlopen(r,timeout=timeout,context=ssl.create_default_context()) as x:return x.status,x.headers.get('content-type','')
def build_osint_engine(root,target='',objective='',collect=False,image_paths=None,username=''):
 image_paths=image_paths or [];d={'schema_version':'146-159.0','target':target,'objective':objective,'collection_requested':bool(collect),'principles':['public_sources_only','consent_first','source_provenance','no_private_access','no_covert_tracking'],'capabilities':{'infrastructure':['certificate_transparency','RDAP/WHOIS research','DNS/subdomain correlation','technology context'],'social':['public profile URL pivots','username pivots','public URL status checks'],'image':['local SHA-256','EXIF/GPS if present','perceptual-fingerprint plan','reverse-image-search links'],'location':['public geodata','asset/IP geolocation research','map query generation'],'timeline':['web archives','certificate dates','source timestamps'],'documents':['public document metadata','hashing','search pivots']},'restrictions':['no phone-number tracking','no IMEI/cell-tower tracking','no covert GPS','no private-account access','no credential harvesting','no doxxing','no stalking']}
 if username:
  u=re.sub(r'[^A-Za-z0-9._-]','',username)[:80];d['social_pivots']=[f'https://{h}/{u}' for h in SOCIAL_HOSTS]
  if collect:
   out=[]
   for url in d['social_pivots']:
    try:s,c=_get(url);out.append({'url':url,'status':s,'content_type':c})
    except Exception as e:out.append({'url':url,'status':None,'error':str(e)[:200]})
   d['social_status_checks']=out
 imgs=[]
 for raw in image_paths:
  p=Path(raw)
  if p.is_file():
   b=p.read_bytes();imgs.append({'path':str(p),'size':len(b),'sha256':hashlib.sha256(b).hexdigest(),'reverse_image_search_links':['https://lens.google.com/','https://www.bing.com/visualsearch','https://images.google.com/'],'exif_note':'GPS metadata, if present, is unverified until corroborated.'})
 d['images']=imgs;d['source_plan']={'CT':'crt.sh/certificate-transparency','archives':'Internet Archive/Common Crawl','registration':'RDAP/WHOIS','profiles':'public pages only','geodata':'public sources for infrastructure/location context','documents':'public documents'};d['generated_at']=datetime.now(timezone.utc).isoformat();return _write(root,'osint-engine-v146-v159.json',d)
