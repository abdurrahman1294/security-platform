"""V3.41 identity protocol assessment matrix, evidence-first and bounded."""
from __future__ import annotations
from pathlib import Path
import hashlib,time
from modules.reliability_execution_integrity_v331 import atomic_write
VERSION="3.41.0"
PROTOCOLS=("kerberos","ldap","ldaps","ntlm","smb","winrm","rdp","ssh","oauth","oidc","saml","mfa","dns-identity")
CHECKS=("configuration","exposure","authentication-policy","authorization-boundary","delegation-trust","certificate-validation","mfa-enforcement","session-policy","directory-permissions","service-account-hygiene")
def _id(*p): return hashlib.sha256("|".join(map(str,p)).encode()).hexdigest()[:20]
def _write(root,name,obj): p=Path(root)/"evidence"/name; atomic_write(p,obj); return p
def build_v341_fabric(root, *, target="", identities=None):
    ids=[{"identity_id":str(x.get("id") or _id("identity",i)),"role":str(x.get("role","operator-supplied")),"source":"operator-supplied","secret_material_collected":False} for i,x in enumerate(identities or []) if isinstance(x,dict)]
    matrix=[{"protocol":p,"checks":list(CHECKS),"active_execution":"specialist/approved procedure","credential_capture":False,"spraying":False,"scope_recheck":True} for p in PROTOCOLS]
    result={"schema_version":VERSION,"target":target,"identities":ids,"protocol_matrix":matrix,"coverage":{"protocols":len(PROTOCOLS),"checks_per_protocol":len(CHECKS)},"governance":{"operator_identities_only":True,"no_secret_collection":True,"no_credential_spraying":True,"no_bypass_execution":True,"specialist_delegation":True},"created_at":time.time()}
    _write(root,"identity-assurance-v341.json",result); return result
def v341_test_matrix():
    names=["13-protocols","10-checks","identity-redaction","operator-identities-only","no-secret-collection","no-spraying","no-bypass","scope-recheck","kerberos","ldap","ntlm","smb","winrm","rdp","ssh","oauth","oidc","saml","mfa","dns-identity","machine-readable","atomic-write"]
    return {"schema_version":VERSION,"scenario_count":len(names),"scenarios":[{"id":_id(x),"name":x,"expected":"bounded-identity-assurance"} for x in names]}
