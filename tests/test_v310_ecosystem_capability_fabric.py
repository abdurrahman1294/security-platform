import json
from modules.ecosystem_capability_fabric_v310 import (
    capability_matrix, import_netexec, import_frida, import_hashcat,
    import_metasploit, import_responder, build_cross_domain_plan,
)

def test_capability_matrix(tmp_path):
    out = capability_matrix(tmp_path, installed_tools=["nxc", "nmap"])
    assert out["status"] == "completed"
    assert (tmp_path / "evidence" / "ecosystem-capability-matrix-v310.json").exists()
    assert any(x["capability"] == "ad_attack_paths" for x in out["capabilities"])

def test_netexec_import(tmp_path):
    src=tmp_path/"nxc.json"; src.write_text(json.dumps({"hostname":"dc01","host":"127.0.0.1","message":"SMB signing"}))
    out=import_netexec(tmp_path,src); assert out["status"]=="completed"; assert out["observations"]

def test_frida_import(tmp_path):
    src=tmp_path/"frida.jsonl"; src.write_text(json.dumps({"package":"com.lab.app","function":"foo","event":"call"})+"\n")
    out=import_frida(tmp_path,src); assert out["observations"][0]["source"]=="Frida"

def test_hashcat_does_not_retain_secrets(tmp_path):
    src=tmp_path/"hashcat.txt"; src.write_text("hash:supersecret\n")
    out=import_hashcat(tmp_path,src); assert out["secret_material_retained"] is False; assert "supersecret" not in json.dumps(out)

def test_metasploit_import_offline(tmp_path):
    src=tmp_path/"msf.json"; src.write_text(json.dumps({"results":[{"module":"demo","host":"127.0.0.1"}]}))
    out=import_metasploit(tmp_path,src); assert out["status"]=="completed"

def test_responder_summary_no_secrets(tmp_path):
    src=tmp_path/"responder.log"; src.write_text("SMB request observed\nNTLM challenge observed\n")
    out=import_responder(tmp_path,src); assert out["secret_material_retained"] is False

def test_cross_domain_plan_is_bounded(tmp_path):
    out=build_cross_domain_plan(tmp_path, observations=[{"source":"BloodHound CE","kind":"ad_attack_path","title":"GenericAll candidate"}])
    assert out["status"]=="completed"; assert out["items"][0]["authorization_required"] is True
