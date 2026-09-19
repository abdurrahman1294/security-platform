from __future__ import annotations
from pathlib import Path
from .atomic_io import atomic_write_json, load_json

def build(root,target=''):
    root=Path(root); ev=root/'evidence'; ev.mkdir(parents=True,exist_ok=True)
    image=load_json(ev/'image-osint-v176.json',{}); locations=load_json(ev/'location-fusion-v198.json',{})
    gps=bool(image.get('gps_present')) or bool(locations.get('locations'))
    data={'schema_version':'177.1','target':target,'methods':['public-geodata','map-context','IP-geolocation-context','landmark correlation','image GPS when present'],'evidence_inputs':{'image_gps_present':gps,'location_fusion_present':bool(locations)},'decision':'EVIDENCE_AVAILABLE' if gps else 'NO_LOCATION_EVIDENCE','restriction':'no covert tracking; no cell-tower/IMEI tracking; corroborate location claims'}
    atomic_write_json(ev/'location-osint-v177.json',data); return data
