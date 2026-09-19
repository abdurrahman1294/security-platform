from __future__ import annotations
import re, shutil
from pathlib import Path
from modules.atomic_io import atomic_write_json
from modules.governed_process_v335 import run_fixed
from modules.security import redact_mapping

VERSION="23.0"

def _run(cmd, timeout=45):
    if not cmd:
        return {"returncode": None, "stdout": "", "stderr": "empty-argv"}
    return run_fixed(Path(cmd[0]).name, cmd, timeout=timeout)


def _which(n): return shutil.which(n)

def inventory(root, interface=""):
    root=Path(root); ev=root/"evidence"; ev.mkdir(parents=True,exist_ok=True)
    results=[]
    if _which("iw"):
        r=_run(["iw","dev"]); results.append({"tool":"iw","action":"device-inventory","returncode":r["returncode"],"stdout":r["stdout"]})
        if interface:
            r2=_run(["iw","dev",interface,"info"]); results.append({"tool":"iw","action":"interface-info","interface":interface,"returncode":r2["returncode"],"stdout":r2["stdout"]})
            r3=_run(["iw","phy"]); results.append({"tool":"iw","action":"phy-list","returncode":r3["returncode"],"stdout":r3["stdout"]})
    if _which("nmcli"):
        r=_run(["nmcli","-t","-f","DEVICE,TYPE,STATE,CONNECTION","device"]); results.append({"tool":"nmcli","action":"device-state","returncode":r["returncode"],"stdout":r["stdout"]})
    if _which("airmon-ng"):
        r=_run(["airmon-ng"]); results.append({"tool":"airmon-ng","action":"capability-check","returncode":r["returncode"],"stdout":r["stdout"]})
    data={"schema_version":VERSION,"status":"completed" if results else "blocked","interface":interface,"results":results,
          "capabilities":["interface_inventory","radio_capability_observation","network_manager_state","passive_capture_planning","pcap_analysis"],
          "restricted_actions":["deauthentication","frame_injection","credential_cracking","evil-twin_operation","uncontrolled_capture"],
          "limitations":["Radio/channel visibility depends on hardware and driver support.","Inventory does not prove exploitability.","Restricted wireless attack actions require a separate operator-controlled lab workflow and are not automated here."]}
    atomic_write_json(ev/"wireless-inventory-v23.json",redact_mapping(data)); return data

def analyze_pcap(root, pcap_path):
    root=Path(root); ev=root/"evidence"; ev.mkdir(parents=True,exist_ok=True); p=Path(pcap_path)
    if not p.is_file(): return {"status":"blocked","reason":"pcap-file-required"}
    tshark=_which("tshark")
    if not tshark: return {"status":"blocked","reason":"tshark-not-installed"}
    fields="frame.time_epoch,wlan.fc.type_subtype,wlan.ssid,wlan.bssid,wlan.sa,wlan.da,radiotap.channel.freq"
    r=_run([tshark,"-r",str(p),"-T","fields","-E","separator=|","-E","quote=d","-e","frame.time_epoch","-e","wlan.fc.type_subtype","-e","wlan.ssid","-e","wlan.bssid","-e","wlan.sa","-e","wlan.da","-e","radiotap.channel.freq"],timeout=120)
    lines=[x for x in r["stdout"].splitlines() if x.strip()][:10000]
    ssids=set(); bssids=set(); channels=set();
    for line in lines:
        parts=line.split("|")
        if len(parts)>=7:
            if parts[2]: ssids.add(parts[2].strip('"'))
            if parts[3]: bssids.add(parts[3].strip('"').lower())
            if parts[6]: channels.add(parts[6].strip('"'))
    data={"schema_version":VERSION,"status":"completed" if r["returncode"]==0 else "failed","pcap":str(p),"records":len(lines),"ssids":sorted(ssids),"bssids":sorted(bssids),"frequencies":sorted(channels),"tool":"tshark","fields":fields}
    atomic_write_json(ev/"wireless-pcap-analysis-v23.json",redact_mapping(data)); return data
