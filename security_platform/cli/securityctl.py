#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, sys
from pathlib import Path as _BootstrapPath
# Support both `python securityctl.py` from this directory and
# `python security_platform/cli/securityctl.py` from the repository root.
_REPO_ROOT = _BootstrapPath(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
from pathlib import Path
from security_platform.core.engagement import Engagement
from security_platform.core.policy import ScopePolicy
from security_platform.core.platform import SecurityPlatform
from security_platform.engines import PentestEngine, OSINTEngine, BugBountyEngine, MobileEngine, WirelessEngine, RemoteEngine

def parser():
    p = argparse.ArgumentParser(prog="securityctl", description="Security Platform: independent pentest, bug-bounty and OSINT engines")
    s = p.add_subparsers(dest="engine", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-c", "--client", required=True)
    common.add_argument("-t", "--target", required=True)
    common.add_argument("-o", "--output-dir", required=True)
    common.add_argument("--scope", default="config/scope.example.txt")

    pp = s.add_parser("pentest", parents=[common], help="run the dedicated authorized pentest engine")
    pp.add_argument("--phases", default="recon,probe,ports,dns,tls,web,api,authenticated,credentials,adaptive,intelligence,final", help="comma-separated phases; optional lab-only validate/reasoning/persistence-validation phases; add ad/aws explicitly when authorized")
    pp.add_argument("--verify-credentials", action="store_true", help="explicitly verify one discovered credential against the local lab verifier (loopback only)")
    pp.add_argument("--credential-id", default="", help="credential ID to verify; verification never sprays multiple credentials")
    pp.add_argument("--show-credentials", action="store_true", help="explicitly print recovered credential values in the operator output")
    pp.add_argument("--authorize", action="store_true", help="explicitly assert authorization; skips the interactive phrase gate for this invocation")

    op = s.add_parser("osint", parents=[common], help="run the dedicated passive/public OSINT engine")
    op.add_argument("--objective", default="general")
    op.add_argument("--input", action="append", default=[])
    op.add_argument("--no-public-collection", action="store_true")

    cp = s.add_parser("cloud", parents=[common], help="run read-only multi-cloud/Kubernetes assessment")
    cp.add_argument("--provider", required=True, choices=["azure", "gcp", "kubernetes"])
    cp.add_argument("--export", default="", help="offline JSON export; when omitted, use fixed read-only provider CLI commands")

    adx = s.add_parser("ad-relationships", parents=[common], help="analyze exported AD ACL/delegation/Kerberos relationships")
    adx.add_argument("--input", required=True, help="JSON/CSV relationship export")

    mp = s.add_parser("mobile", parents=[common], help="run Android/mobile security assessment")
    mp.add_argument("--apk", required=True, help="path to an APK for static assessment")
    mp.add_argument("--dynamic", action="store_true", help="run read-only ADB inspection; emulator by default")
    mp.add_argument("--serial", default="", help="ADB serial; required when multiple devices are connected")
    mp.add_argument("--allow-physical", action="store_true", help="explicitly allow read-only inspection of a physical device")

    ip = s.add_parser("ios", parents=[common], help="run safe static iOS IPA assessment")
    ip.add_argument("--ipa", required=True)

    idp = s.add_parser("ios-dynamic", parents=[common], help="run bounded iOS Simulator runtime inspection")
    idp.add_argument("--bundle-id", default="")
    idp.add_argument("--device", default="booted")
    idp.add_argument("--export", default="", help="offline simulator runtime JSON export")
    idp.add_argument("--allow-launch", action="store_true", help="explicitly launch the exact bundle ID in the simulator")

    bl = s.add_parser("ble", parents=[common], help="analyze passive BLE scan export")
    bl.add_argument("--input", required=True, help="JSON/CSV scan export")

    ctr = s.add_parser("container", parents=[common], help="run offline container-image static security assessment")
    ctr.add_argument("--archive", required=True, help="OCI/Docker image archive; never executed")

    db = s.add_parser("database", parents=[common], help="analyze normalized database-service exposure export")
    db.add_argument("--input", required=True, help="JSON service inventory")

    nd = s.add_parser("network-config", parents=[common], help="review an exported network-device configuration")
    nd.add_argument("--input", required=True, help="text configuration export")

    wp = s.add_parser("wireless", parents=[common], help="run wireless inventory/passive assessment")
    wp.add_argument("--interface", default="")
    wp.add_argument("--pcap", default="", help="analyze an existing PCAP/PCAPNG capture")

    rp = s.add_parser("remote", parents=[common], help="run controlled remote-system assessment against the disposable lab")
    rp.add_argument("--scenarios", default="", help="comma-separated lab scenarios; default is the full controlled catalog")
    rp.add_argument("--internal-target", default="")
    rp.add_argument("--execute", action="store_true", help="execute fixed benign lab proof fixtures")
    rp.add_argument("--authorize", action="store_true", help="assert explicit authorization for the lab engagement")
    rp.add_argument("--roe", default="", help="ROE JSON permitting controlled_attack_chain_test")

    adp = s.add_parser("adaptive", parents=[common], help="build an evidence-driven adaptive assessment plan for unusual/unknown target behavior")
    adp.add_argument("--authorize", action="store_true", help="record that the operator has asserted authorization; does not expand scope or grant execution authority")

    inv = s.add_parser("investigate", parents=[common], help="run the persistent evidence-driven adaptive investigation loop")
    inv.add_argument("--authorize", action="store_true", help="record that the operator has asserted authorization; does not grant execution authority")
    inv.add_argument("--iterations", type=int, default=1, help="bounded state-update iterations (1-10)")

    osp = s.add_parser("opsec", parents=[common], help="audit operational privacy and artifact hygiene (no anonymity/anti-forensics)")
    osp.add_argument("--operator-alias", default="operator")

    bp = s.add_parser("bounty", parents=[common], help="run the dedicated program-aware bounty engine")
    bp.add_argument("--program-name", default="")
    bp.add_argument("--program-policy", required=True)
    bp.add_argument("--asset", action="append", default=[])
    bp.add_argument("--execute", action="store_true", help="explicitly request active, authorized bounty testing")
    bp.add_argument("--authorize", action="store_true", help="explicitly assert authorization for active program testing")

    xp = s.add_parser("platform", parents=[common], help="coordinate multiple specialists without sharing authority")
    xp.add_argument("--engines", default="osint,pentest,bounty", help="comma-separated specialist names")
    xp.add_argument("--phases", default="recon,probe,ports,dns,tls,web,api,authenticated,credentials,adaptive,intelligence,final", help="comma-separated pentest phases; add ad/aws explicitly when authorized")
    xp.add_argument("--verify-credentials", action="store_true")
    xp.add_argument("--credential-id", default="")
    xp.add_argument("--show-credentials", action="store_true")
    xp.add_argument("--objective", default="general")
    xp.add_argument("--input", action="append", default=[])
    xp.add_argument("--no-public-collection", action="store_true")
    xp.add_argument("--program-name", default="")
    xp.add_argument("--program-policy", default="")
    xp.add_argument("--asset", action="append", default=[])
    xp.add_argument("--execute", action="store_true")
    xp.add_argument("--apk", default="")
    xp.add_argument("--mobile-dynamic", action="store_true")
    xp.add_argument("--mobile-serial", default="")
    xp.add_argument("--mobile-allow-physical", action="store_true")
    xp.add_argument("--wireless-interface", default="")
    xp.add_argument("--wireless-pcap", default="")
    xp.add_argument("--remote-scenarios", default="")
    xp.add_argument("--remote-internal-target", default="")
    xp.add_argument("--remote-execute", action="store_true")
    xp.add_argument("--maturity", action="store_true", help="build the operational maturity and expert capability report without running active tests")
    xp.add_argument("--capability-audit", action="store_true", help="audit major expert pentest/red-team activities against implemented, executable and human-led coverage")

    ap = s.add_parser("autonomy", parents=[common], help="run the policy-controlled autonomous controller")
    ap.add_argument("--profile", choices=["observe", "recon", "assess", "safe-verify", "assisted"], default="assess")
    ap.add_argument("--cycles", type=int, default=1)
    ap.add_argument("--execute", action="store_true", help="permit execution of allowlisted R0-R2 handlers/tools; authorization is still required")
    ap.add_argument("--authorize", action="store_true", help="assert explicit written authorization for this engagement")
    ap.add_argument("--roe", default="", help="machine-readable engagement ROE JSON")
    ap.add_argument("--request-action", default="", help="queue one approval request instead of running the loop")
    ap.add_argument("--request-reason", default="", help="reason attached to an approval request")
    ap.add_argument("--approve", default="", help="approve a pending request and print a single-use token")
    ap.add_argument("--deny", default="", help="deny a pending request")
    ap.add_argument("--list-pending", action="store_true")

    ms = s.add_parser("mission", parents=[common], help="build the bounded evidence-driven assessment mission plan")
    ms.add_argument("--authorize", action="store_true", help="assert explicit authorization for planning; does not expand scope")

    ex = s.add_parser("ecosystem", parents=[common], help="integrate evidence and capability metadata from major open-source security ecosystems")
    ex.add_argument("--action", required=True, choices=["matrix", "bloodhound", "mobsf", "findings", "netexec", "frida", "hashcat", "metasploit", "responder", "plan"])
    ex.add_argument("--input", default="", help="BloodHound JSON, MobSF JSON, or external findings JSON/JSONL")
    ex.add_argument("--source-name", default="external", help="provenance label for imported findings")
    sf = s.add_parser("fabric", parents=[common], help="run the superior cross-ecosystem capability fabric")
    sf.add_argument("--action", required=True, choices=["plan", "sarif", "correlate", "browser-trace", "continuous", "benchmark", "model-routing", "attack-catalog", "adaptive", "fusion", "coverage", "mission-plan", "request-approvals", "execute", "delta", "nonlinear", "clues", "control-validation", "revalidate", "remediation", "fabric", "specialists", "wireless-domain", "mobile-domain", "remote-domain", "rce-domain", "domain-fusion", "embedded", "firmware-domain", "ot-domain", "automotive-domain", "hardware-domain", "iot-domain", "network-device-domain", "remote-endpoint", "remote-mobile", "advanced-analysis", "v317-fabric", "remote-file-access", "cellular-perspective", "execution-adapters", "v318-fabric", "cellular-universal", "cellular-probe-contract", "universal-surfaces", "perspectives", "factor-graph", "universal-plan", "universal-assess", "specialist-router", "r4-capabilities", "r4-execute", "execution-graph", "assessment-intelligence", "attack-paths", "capability-runtime", "capability-catalog", "temporal-twin", "payload-assurance", "adversary-simulation", "adversary-simulation-suite", "unified-assess", "unified-assess-suite", "reliability-integrity", "reliability-integrity-suite", "coverage-assurance", "coverage-assurance-suite", "validation-assurance", "validation-assurance-suite", "evidence-report", "evidence-report-suite", "engine-self-security", "engine-self-security-suite", "capability-benchmark", "capability-benchmark-suite", "unified-specialist-adapters", "web-api-assurance", "fuzz-campaign", "engagement-datastore", "identity-assurance", "capability-closure", "capability-closure-suite", "assurance-stack", "complete-testing-lab", "complete-testing-lab-suite", "realistic-vulnerability-lab", "realistic-vulnerability-campaign", "realistic-vulnerability-lab-suite", "integration-validation-range", "integration-validation-campaign", "campaign-quality", "campaign-resilience", "multi-target-integration", "multi-target-campaign", "multi-target-suite", "self-assessment", "adversarial-matrix", "adversarial-reasoning", "reasoning-suite", "final-engine", "final-engine-suite"])
    sf.add_argument("--input", default="", help="SARIF or HAR/HTTP trace input for the selected action")
    sf.add_argument("--source-name", default="SARIF", help="source label for SARIF imports")
    sf.add_argument("--runtime-artifact", default="", help="evidence artifact used for source/runtime correlation")
    sf.add_argument("--baseline", default="", help="previous continuous-assurance artifact")
    sf.add_argument("--objective", default="general")
    sf.add_argument("--platform", default="auto", choices=["auto", "windows", "linux", "macos", "android", "ios"])
    sf.add_argument("--authorize", action="store_true", help="assert explicit authorization for governed execution")
    sf.add_argument("--roe", default="", help="machine-readable ROE JSON for governed R4 procedures")
    sf.add_argument("--approval-token", action="append", default=[], help="request_id=single-use-token; repeat for multiple approved steps")
    sf.add_argument("--approved-path", action="append", default=[], help="explicit remote file/directory path for file-access action; repeat as needed")
    sf.add_argument("--write-probe", action="store_true", help="request a single disposable write-marker test; still requires governed approval")
    sf.add_argument("--perspective", default="internet_ipv4", choices=["local_host","physical_adjacent","lan","enterprise","internet_ipv4","internet_ipv6","cellular_ipv4","cellular_ipv6","vpn","cloud_vantage","authenticated_user","admin_authenticated","testbed","physical_lab"])
    sf.add_argument("--max-steps", type=int, default=8, help="bounded governed mission steps (1-20)")
    sf.add_argument("--execute", action="store_true", help="execute bounded registered R0-R2 universal adapters; still requires --authorize and an in-scope target")
    sf.add_argument("--timeout", type=int, default=600, help="per-tool timeout for universal assessment (1-900 seconds)")
    mx = s.add_parser("matrix", parents=[common], help="write executable capability matrix for this deployment")
    rt = s.add_parser("redteam-support", parents=[common], help="generate human-led red team support pack")
    rt.add_argument("--domain", default="")
    rt.add_argument("--dc-ip", default="")
    st = s.add_parser("self-test", help="run adversarial control-plane self-test")
    st.add_argument("-o", "--output-dir", default="output/self-test")

    en = s.add_parser("engage", parents=[common], help="run full authorized engagement runner")
    en.add_argument("--authorize", action="store_true")
    en.add_argument("--in-scope", action="store_true")
    en.add_argument("--execute", action="store_true", help="allow real tool executor during recon_seed")
    en.add_argument("--no-resume", action="store_true")
    ck = s.add_parser("cockpit", parents=[common], help="build operator cockpit snapshot")
    lc = s.add_parser("lab-cert", help="run disposable lab certification suite")
    lc.add_argument("-o", "--output-dir", default="output/lab-cert")

    hr = s.add_parser("high-risk", parents=[common], help="operator-controlled high-risk capability gates")
    hr.add_argument("--roe", default="", help="path to ROE JSON allowing high-risk actions")
    hr.add_argument("--status", action="store_true")
    hr.add_argument("--enable", default="", help="action to enable: rce_chain|password_spray|lateral_movement|persistence|exfiltration_simulation")
    hr.add_argument("--disable", default="", help="action to disable")
    hr.add_argument("--master-phrase", default="")
    hr.add_argument("--action-phrase", default="")
    hr.add_argument("--authorize", action="store_true")
    hr.add_argument("--kill-switch", action="store_true")
    hr.add_argument("--clear-kill-switch", action="store_true")
    hr.add_argument("--run-supervised", default="", help="create supervised plan for an enabled action (single-use)")
    hr.add_argument("--token", default="", help="enablement token for supervised run")
    pf = s.add_parser("authorized-proof", parents=[common], help="run bounded authorized proof technique (approval required)")
    pf.add_argument("--technique", required=True, choices=["reflected_marker","open_redirect","sqli_boolean","security_headers"])
    pf.add_argument("--url", required=True, help="in-scope target URL")
    pf.add_argument("--approve-proof", action="store_true", help="operator approval for this proof")
    pb = s.add_parser("exploit-playbooks", parents=[common], help="generate authorized exploitation playbooks")

    ac = s.add_parser("attack-chain", parents=[common], help="run the controlled disposable-local-lab attack chain")
    ac.add_argument("--internal-target", default="http://127.0.0.1:8082")
    ac.add_argument("--execute", action="store_true", help="execute the lab-only controlled chain")
    ac.add_argument("--authorize", action="store_true", help="assert explicit authorization for the lab engagement")
    ac.add_argument("--roe", required=True, help="machine-readable ROE JSON permitting the specific R4 lab action")
    ac.add_argument("--approval-token", default="", help="single-use approval token bound to controlled_attack_chain_test")

    s.add_parser("engines", help="show installed specialist engines")
    s.add_parser("preflight", parents=[common], help="check target/scope readiness without active testing")
    pr = s.add_parser("pretest-readiness", parents=[common], help="verify repository and environment readiness before engine testing")
    pr.add_argument("--repo-root", default="", help="repository root to validate")
    s.add_parser("tools", help="show hardened toolchain status")
    fu = s.add_parser("fusion", parents=[common], help="run the V5.0 capability-fusion control plane")
    fu.add_argument("--objective", default="full-assessment")
    fu.add_argument("--authorize", action="store_true", help="assert explicit authorization for governed planning")
    fu.add_argument("--mcp-list", action="store_true", help="print the MCP-compatible tool list")


    f51 = s.add_parser("fusion-v51", parents=[common], help="V5.1 PTT/agent-cycle/findings-import control plane")
    f51.add_argument("--action", default="status", choices=["status", "episode", "import", "port-pipeline", "sarif", "offline-roles", "register-images"])
    f51.add_argument("--objective", default="authorized assessment")
    f51.add_argument("--import-files", nargs="*", default=[])
    f51.add_argument("--image-files", nargs="*", default=[])
    f51.add_argument("--installed-tools", default="nmap,httpx,nuclei,naabu,subfinder,katana")
    f51.add_argument("--raw-output-file", default="")

    d52 = s.add_parser("depth-v52", parents=[common], help="V5.2 adapters/MCP/supervisor/retest/reports/benchmark")
    d52.add_argument("--action", default="status", choices=["status", "run-adapter", "import", "propose", "snapshot", "diff", "report", "benchmark", "mcp-list"])
    d52.add_argument("--tool", default="nmap")
    d52.add_argument("--dry-run", action="store_true")
    d52.add_argument("--import-files", nargs="*", default=[])
    d52.add_argument("--provider", default="heuristic")
    d52.add_argument("--snapshot-label", default="default")
    d52.add_argument("--diff-a", default="")
    d52.add_argument("--diff-b", default="")

    u53 = s.add_parser("unified-v53", parents=[common], help="V5.3 unified core: audit, mission, browser, malware-static, phishing-sim, adversary, graph")
    u53.add_argument("--action", default="status", choices=["status","audit","mission","browser","malware-static","phishing-sim","adversary","attack-graph","web-advanced","command-center"])
    u53.add_argument("--sample", default="")
    u53.add_argument("--org", default="lab-org")
    u53.add_argument("--scenario", default="credential-awareness")
    u53.add_argument("--url", default="")
    s.add_parser("intelligence", parents=[common], help="build V3.8 intelligence fabric and coverage artifacts")
    rg = s.add_parser("range-gate", parents=[common], help="run the local multi-target end-to-end assurance gate")
    rg.add_argument("--repo-root", default="", help="repository root used for specialist-tool readiness inventory")
    sc = s.add_parser("specialist-conformance", parents=[common], help="audit specialist/domain conformance and tool readiness")
    sir = s.add_parser("specialist-isolated-range", parents=[common], help="run disposable isolated specialist target range")
    sir.add_argument("--no-execute", action="store_true", help="only validate isolated-range readiness; do not execute")
    sc.add_argument("--repo-root", default="", help="repository root used for specialist-tool readiness inventory")
    sti = s.add_parser("specialist-tool-integration", parents=[common], help="run installed allowlisted tools against the disposable loopback lab")
    sti.add_argument("--no-execute", action="store_true", help="only validate integration readiness; do not execute installed tools")
    s.add_parser("tool-evidence-normalization", parents=[common], help="normalize collected allowlisted-tool output into canonical evidence")
    s.add_parser("tool-aware-specialist-plan", parents=[common], help="build a bounded tool-aware specialist plan without executing it")

    return p

def _engagement(a):
    e = Engagement(a.client, a.target, Path(a.output_dir).resolve(), Path(a.scope).resolve())
    e.output.mkdir(parents=True, exist_ok=True)
    return e

def main(argv=None):
    a = parser().parse_args(argv)
    if a.engine == "engines":
        print(json.dumps(SecurityPlatform(Engagement("catalog", "catalog", Path.cwd())).catalog(), indent=2)); return 0
    if a.engine == "platform" and (getattr(a, "maturity", False) or getattr(a, "capability_audit", False)):
        e = _engagement(a)
        if getattr(a, "capability_audit", False) and not getattr(a, "maturity", False):
            from modules.expert_capability_audit_v27 import build
            from security_platform.core.tools import inventory
            out = build(e.output, tool_inventory=[x.__dict__ for x in inventory()])
            print(json.dumps(out, indent=2)); return 0
        e = _engagement(a)
        out = SecurityPlatform(e).maturity()
        print(json.dumps(out, indent=2)); return 0
    if a.engine == "pretest-readiness":
        e = _engagement(a)
        from modules.pretest_readiness_v355 import run_pretest_readiness
        out = run_pretest_readiness(a.repo_root or str(_REPO_ROOT), e.output)
        print(json.dumps(out, indent=2)); return 0 if out.get("status") == "PASS" else 2
    if a.engine == "preflight":
        from security_platform.core.preflight import check
        print(json.dumps(check(a.target, Path(a.scope).resolve()).to_dict(), indent=2)); return 0
    if a.engine == "range-gate":
        e = _engagement(a)
        from modules.range_assurance_gate_v349 import build_gate
        out = build_gate(e.output, repo_root=(a.repo_root or str(_REPO_ROOT)))
        print(json.dumps(out, indent=2)); return 0 if out.get("status") == "PASS" else 2

    if a.engine == "specialist-isolated-range":
        e = _engagement(a)
        from modules.specialist_isolated_range_v354 import run_specialist_range
        out = run_specialist_range(e.output, execute=not a.no_execute)
        print(json.dumps(out, indent=2)); return 0 if out.get("status") == "PASS" else 2
    if a.engine == "specialist-conformance":
        e = _engagement(a)
        from modules.specialist_conformance_v350 import build_conformance
        out = build_conformance(e.output, repo_root=(a.repo_root or str(_REPO_ROOT)))
        print(json.dumps(out, indent=2)); return 0 if out.get("status") == "PASS" else 2
    if a.engine == "specialist-tool-integration":
        e = _engagement(a)
        from modules.specialist_tool_integration_v351 import run_tool_integration
        out = run_tool_integration(e.output, execute=not a.no_execute)
        print(json.dumps(out, indent=2)); return 0 if out.get("status") == "PASS" else 2
    if a.engine == "tool-evidence-normalization":
        e = _engagement(a)
        from modules.tool_evidence_normalization_v352 import normalize_files
        out = normalize_files(e.output, [])
        print(json.dumps(out, indent=2)); return 0 if out.get("status") in {"PASS","PARTIAL"} else 2
    if a.engine == "tool-aware-specialist-plan":
        e = _engagement(a)
        from modules.tool_aware_specialist_planner_v353 import build_plan
        out = build_plan(e.output)
        print(json.dumps(out, indent=2)); return 0 if out.get("status") == "PASS" else 2

    if a.engine == "intelligence":
        e = _engagement(a)
        out = SecurityPlatform(e).intelligence_v38()
        print(json.dumps(out, indent=2)); return 0

    if a.engine == "ecosystem":
        e = _engagement(a)
        from modules.ecosystem_adapters_v39 import build_ecosystem_matrix, import_bloodhound, import_mobsf, import_findings
        from modules.ecosystem_capability_fabric_v310 import capability_matrix, import_netexec, import_frida, import_hashcat, import_metasploit, import_responder, build_cross_domain_plan
        if a.action == "matrix":
            from security_platform.core.tools import inventory
            installed = [x.name for x in inventory() if x.status == "ready"]
            legacy = build_ecosystem_matrix(e.output, installed_tools=installed)
            current = capability_matrix(e.output, installed_tools=installed)
            out = {**current, "legacy_ecosystems": legacy.get("ecosystems", []), "high_risk_exclusions": legacy.get("high_risk_exclusions", [])}
        elif a.action == "bloodhound":
            if not a.input: raise SystemExit("--input is required for --action bloodhound")
            out = import_bloodhound(e.output, a.input)
        elif a.action == "mobsf":
            if not a.input: raise SystemExit("--input is required for --action mobsf")
            out = import_mobsf(e.output, a.input)
        elif a.action == "findings":
            if not a.input: raise SystemExit("--input is required for --action findings")
            out = import_findings(e.output, a.input, source_name=a.source_name)
        elif a.action == "netexec":
            if not a.input: raise SystemExit("--input is required for --action netexec")
            out = import_netexec(e.output, a.input)
        elif a.action == "frida":
            if not a.input: raise SystemExit("--input is required for --action frida")
            out = import_frida(e.output, a.input)
        elif a.action == "hashcat":
            if not a.input: raise SystemExit("--input is required for --action hashcat")
            out = import_hashcat(e.output, a.input)
        elif a.action == "metasploit":
            if not a.input: raise SystemExit("--input is required for --action metasploit")
            out = import_metasploit(e.output, a.input)
        elif a.action == "responder":
            if not a.input: raise SystemExit("--input is required for --action responder")
            out = import_responder(e.output, a.input)
        else:
            observations = []
            evidence_dir = e.output / "evidence"
            if evidence_dir.exists():
                for fp in sorted(evidence_dir.glob("*-import-v310.json")):
                    try:
                        obj = json.loads(fp.read_text(encoding="utf-8"))
                    except (OSError, json.JSONDecodeError):
                        continue
                    observations.extend(obj.get("observations", []))
                    observations.extend(obj.get("findings", []))
            out = build_cross_domain_plan(e.output, observations=observations)
        print(json.dumps(out, indent=2)); return 0 if out.get("status") == "completed" else 2

    if a.engine == "fabric":
        e = _engagement(a)
        from modules.superior_capability_fabric_v311 import (
            build_agentic_plan, import_sarif, correlate_source_runtime,
            import_browser_trace, build_continuous_assurance, build_benchmark_metrics,
            build_model_routing_plan, import_attack_emulation_catalog,
        )
        from modules.adaptive_mission_controller_v312 import build_adaptive_mission, build_capability_fusion_matrix
        from modules.governed_mission_fabric_v313 import (
            build_workflow_coverage, build_governed_execution_plan, request_approvals, execute_approved
        )
        from modules.exposure_validation_fabric_v314 import (
            build_capability_delta, build_nonlinear_mission, record_clues,
            build_control_validation, build_continuous_revalidation, build_remediation_retest, build_v314_fabric
        )
        if a.action == "plan":
            out = build_agentic_plan(e.output, a.target, a.objective)
        elif a.action == "sarif":
            if not a.input: raise SystemExit("--input is required for --action sarif")
            out = import_sarif(e.output, a.input, a.source_name)
        elif a.action == "correlate":
            out = correlate_source_runtime(e.output, runtime_artifact=a.runtime_artifact)
        elif a.action == "browser-trace":
            if not a.input: raise SystemExit("--input is required for --action browser-trace")
            out = import_browser_trace(e.output, a.input)
        elif a.action == "model-routing":
            out = build_model_routing_plan(e.output, a.objective)
        elif a.action == "attack-catalog":
            if not a.input: raise SystemExit("--input is required for --action attack-catalog")
            out = import_attack_emulation_catalog(e.output, a.input)
        elif a.action == "continuous":
            out = build_continuous_assurance(e.output, baseline=a.baseline)
        elif a.action == "adaptive":
            out = build_adaptive_mission(e.output, a.target, a.objective, authorized=False)
        elif a.action == "fusion":
            out = build_capability_fusion_matrix(e.output)
        elif a.action == "coverage":
            out = build_workflow_coverage(e.output)
        elif a.action == "mission-plan":
            out = build_governed_execution_plan(e.output, a.target, a.objective, a.max_steps)
        elif a.action == "request-approvals":
            out = request_approvals(e.output, a.target, a.objective, a.max_steps)
        elif a.action == "execute":
            tokens = {}
            for item in a.approval_token:
                if "=" not in item:
                    raise SystemExit("--approval-token must be request_id=token")
                rid, token = item.split("=", 1)
                if not rid or not token:
                    raise SystemExit("--approval-token must be request_id=token")
                tokens[rid] = token
            out = execute_approved(e.output, a.target, e.scope_file, objective=a.objective, max_steps=a.max_steps, authorization=bool(a.authorize), approval_tokens=tokens)
        elif a.action == "delta":
            out = build_capability_delta(e.output)
        elif a.action == "nonlinear":
            out = build_nonlinear_mission(e.output, a.target, a.objective)
        elif a.action == "clues":
            observations = []
            if a.input:
                try:
                    obj = json.loads(Path(a.input).read_text(encoding="utf-8"))
                    observations = obj if isinstance(obj, list) else obj.get("observations", obj.get("findings", []))
                except Exception as exc:
                    raise SystemExit(f"invalid clue input: {exc}")
            out = record_clues(e.output, observations)
        elif a.action == "control-validation":
            techniques = [x.strip() for x in a.input.split(",") if x.strip()] if a.input else []
            out = build_control_validation(e.output, techniques)
        elif a.action == "revalidate":
            baseline = {}
            if a.baseline:
                try:
                    baseline = json.loads(Path(a.baseline).read_text(encoding="utf-8"))
                except Exception as exc:
                    raise SystemExit(f"invalid baseline: {exc}")
            out = build_continuous_revalidation(e.output, baseline)
        elif a.action == "remediation":
            findings = []
            if a.input:
                try:
                    obj = json.loads(Path(a.input).read_text(encoding="utf-8"))
                    findings = obj if isinstance(obj, list) else obj.get("findings", obj.get("items", []))
                except Exception as exc:
                    raise SystemExit(f"invalid findings input: {exc}")
            out = build_remediation_retest(e.output, findings)
        elif a.action in {"final-engine", "final-engine-suite"}:
            if a.action == "final-engine-suite":
                from modules.final_capability_closure_v360 import v360_test_matrix
                out = v360_test_matrix()
            else:
                out = SecurityPlatform(e).final_engine_closure(objective=a.objective)
            print(json.dumps(out, indent=2)); return 0
        elif a.action == "fabric":
            out = build_v314_fabric(e.output, a.target, a.objective)
        elif a.action in {"specialists", "wireless-domain", "mobile-domain", "remote-domain", "rce-domain", "domain-fusion", "embedded", "firmware-domain", "ot-domain", "automotive-domain", "hardware-domain", "iot-domain", "network-device-domain", "remote-endpoint", "remote-mobile", "advanced-analysis", "v317-fabric", "remote-file-access", "cellular-perspective", "execution-adapters", "v318-fabric", "cellular-universal", "cellular-probe-contract", "universal-surfaces", "perspectives", "factor-graph", "universal-plan", "universal-assess", "specialist-router", "r4-capabilities", "r4-execute", "execution-graph", "assessment-intelligence", "attack-paths", "capability-runtime", "capability-catalog", "temporal-twin", "payload-assurance", "adversary-simulation", "adversary-simulation-suite", "unified-assess", "unified-assess-suite", "reliability-integrity", "reliability-integrity-suite", "coverage-assurance", "coverage-assurance-suite", "validation-assurance", "validation-assurance-suite", "evidence-report", "evidence-report-suite", "engine-self-security", "engine-self-security-suite", "capability-benchmark", "capability-benchmark-suite", "unified-specialist-adapters", "web-api-assurance", "fuzz-campaign", "engagement-datastore", "identity-assurance", "capability-closure", "capability-closure-suite", "assurance-stack", "complete-testing-lab", "complete-testing-lab-suite", "realistic-vulnerability-lab", "realistic-vulnerability-campaign", "realistic-vulnerability-lab-suite", "integration-validation-range", "integration-validation-campaign", "campaign-quality", "campaign-resilience", "multi-target-integration", "multi-target-campaign", "multi-target-suite", "self-assessment", "adversarial-matrix", "adversarial-reasoning", "reasoning-suite"}:
            from modules.specialist_domain_fabric_v315 import (build_v315_fabric, capability_matrix, build_wireless_plan, build_mobile_lab_plan, build_remote_matrix, build_rce_validation_catalog, build_domain_fusion)
            from modules.embedded_ot_automotive_fabric_v316 import (build_v316_fabric, build_firmware_pipeline, build_ot_ics_plan, build_automotive_plan, build_hardware_plan, build_iot_network_plan, build_network_device_plan, build_embedded_fusion)
            from modules.remote_endpoint_and_advanced_fabric_v317 import (build_v317_fabric, build_remote_computer_plan, build_remote_mobile_plan, build_advanced_analysis_fabric)
            from modules.remote_endpoint_and_advanced_fabric_v318 import (build_v318_fabric, build_remote_file_access_plan, build_cellular_perspective_plan, build_execution_adapter_catalog)
            from modules.cellular_universal_fabric_v319 import (build_v319_fabric, build_universal_cellular_surface, build_cellular_probe_contract)
            from modules.universal_attack_surface_fabric_v320 import (build_v320_fabric, build_attack_surface_inventory, build_perspective_matrix, build_factor_graph, build_functional_assessment_plan)
            if a.action == "specialists": out = build_v315_fabric(e.output, a.target, a.objective)
            elif a.action == "wireless-domain": out = build_wireless_plan(e.output, a.target)
            elif a.action == "mobile-domain": out = build_mobile_lab_plan(e.output, a.target)
            elif a.action == "remote-domain": out = build_remote_matrix(e.output, a.target)
            elif a.action == "rce-domain": out = build_rce_validation_catalog(e.output)
            elif a.action == "embedded": out = build_v316_fabric(e.output, a.target, a.objective)
            elif a.action == "firmware-domain": out = build_firmware_pipeline(e.output, a.target, a.input)
            elif a.action == "ot-domain": out = build_ot_ics_plan(e.output, a.target, a.objective)
            elif a.action == "automotive-domain": out = build_automotive_plan(e.output, a.target, a.objective)
            elif a.action == "hardware-domain": out = build_hardware_plan(e.output, a.target, a.objective)
            elif a.action == "iot-domain": out = build_iot_network_plan(e.output, a.target, a.objective)
            elif a.action == "network-device-domain": out = build_network_device_plan(e.output, a.target, a.objective)
            elif a.action == "remote-endpoint": out = build_remote_computer_plan(e.output, a.target, getattr(a, "platform", "auto"), a.objective)
            elif a.action == "remote-mobile": out = build_remote_mobile_plan(e.output, a.target, getattr(a, "platform", "auto"), a.objective)
            elif a.action == "advanced-analysis": out = build_advanced_analysis_fabric(e.output, a.target, a.input, a.objective)
            elif a.action == "v317-fabric": out = build_v317_fabric(e.output, a.target, a.objective, getattr(a, "platform", "auto"), a.input)
            elif a.action == "remote-file-access": out = build_remote_file_access_plan(e.output, a.target, getattr(a, "platform", "auto"), a.approved_path or ([x for x in a.input.split(",") if x.strip()] if a.input else []), a.write_probe)
            elif a.action == "cellular-perspective": out = build_cellular_perspective_plan(e.output, a.target, a.objective)
            elif a.action == "execution-adapters": out = build_execution_adapter_catalog(e.output)
            elif a.action == "v318-fabric": out = build_v318_fabric(e.output, a.target, a.objective, getattr(a, "platform", "auto"), a.input)
            elif a.action == "cellular-universal": out = build_v319_fabric(e.output, a.target, a.objective, [int(x) for x in a.approved_path if x.isdigit()], [])
            elif a.action == "cellular-probe-contract": out = build_cellular_probe_contract(e.output, a.target, [int(x) for x in a.approved_path if x.isdigit()], [])
            elif a.action == "universal-surfaces": out = build_attack_surface_inventory(e.output, target=a.target)
            elif a.action == "perspectives": out = build_perspective_matrix(e.output, target=a.target)
            elif a.action == "factor-graph": out = build_factor_graph(e.output, target=a.target)
            elif a.action == "universal-plan": out = build_v320_fabric(e.output, target=a.target, perspective=getattr(a, "perspective", "internet_ipv4"), authorized=getattr(a, "authorize", False))
            elif a.action == "universal-assess":
                from modules.universal_assessment_runner_v321 import execute_universal_assessment
                selected = [x.strip() for x in a.input.split(",") if x.strip()] if a.input else None
                out = execute_universal_assessment(e.output, target=a.target, scope_file=e.scope_file, perspective=getattr(a, "perspective", "internet_ipv4"), authorized=getattr(a, "authorize", False), execute=getattr(a, "execute", False), surfaces=selected, max_steps=getattr(a, "max_steps", 12), timeout=getattr(a, "timeout", 600))
            elif a.action == "specialist-router":
                from modules.universal_specialist_router_v322 import execute_universal_router
                selected = [x.strip() for x in a.input.split(",") if x.strip()] if a.input else None
                out = execute_universal_router(e.output, target=a.target, scope_file=e.scope_file, perspective=getattr(a, "perspective", "internet_ipv4"), authorized=getattr(a, "authorize", False), execute=getattr(a, "execute", False), surfaces=selected, max_steps=getattr(a, "max_steps", 12), timeout=getattr(a, "timeout", 600), objective=a.objective)
            elif a.action == "r4-capabilities":
                from modules.universal_specialist_router_v322 import build_r4_capability_matrix
                out = build_r4_capability_matrix(e.output, target=a.target)
            elif a.action in {"assessment-intelligence", "attack-paths"}:
                from modules.universal_assessment_intelligence_v324 import build_v324_fabric, build_attack_paths, ingest_baseline
                observations = []
                if a.baseline:
                    try:
                        observations = ingest_baseline(a.baseline)
                    except Exception as exc:
                        raise SystemExit(f"invalid baseline: {exc}")
                if a.action == "attack-paths":
                    out = build_attack_paths(e.output, target=a.target, observations=observations, objective=a.objective, max_paths=getattr(a, "max_steps", 12))
                else:
                    out = build_v324_fabric(e.output, target=a.target, observations=observations, objective=a.objective, max_paths=getattr(a, "max_steps", 12))
            elif a.action in {"capability-runtime", "capability-catalog"}:
                from modules.capability_runtime_v325 import build_runtime_state, capability_catalog, run_bounded_runtime
                if a.action == "capability-catalog":
                    out = {"schema_version": "3.25.0", "status": "ready", "capabilities": capability_catalog()}
                elif getattr(a, "execute", False):
                    selected=[x.strip() for x in a.input.split(",") if x.strip()] if a.input else None
                    out=run_bounded_runtime(e.output,target=a.target,scope_file=e.scope_file,perspective=getattr(a,"perspective","internet_ipv4"),objective=a.objective,authorized=getattr(a,"authorize",False),execute=True,surfaces=selected,max_steps=getattr(a,"max_steps",1),timeout=getattr(a,"timeout",600))
                else:
                    completed=[]; evidence=[]
                    if a.baseline:
                        try:
                            raw=json.loads(Path(a.baseline).read_text(encoding="utf-8"))
                            if isinstance(raw,dict):
                                completed=raw.get("completed",[]); evidence=raw.get("evidence_inputs",[])
                        except Exception as exc:
                            raise SystemExit(f"invalid baseline: {exc}")
                    out=build_runtime_state(e.output,target=a.target,perspective=getattr(a,"perspective","internet_ipv4"),objective=a.objective,authorized=getattr(a,"authorize",False),execute=False,completed=completed,evidence=evidence,limit=getattr(a,"max_steps",8))
            elif a.action in {"temporal-twin", "payload-assurance"}:
                from modules.temporal_digital_twin_v328 import build_v328_fabric, payload_assurance_catalog
                if a.action == "payload-assurance":
                    out = {"schema_version": "3.28.0", "status": "ready", "catalog": payload_assurance_catalog()}
                    print(json.dumps(out, indent=2)); return 0
                assets = None; chains = []; timeline = []
                if a.baseline:
                    try:
                        raw = json.loads(Path(a.baseline).read_text(encoding="utf-8"))
                        if isinstance(raw, dict):
                            assets = raw.get("assets")
                            chains = raw.get("chains", raw.get("attack_paths", []))
                            timeline = raw.get("timeline", raw.get("events", []))
                    except Exception as exc:
                        raise SystemExit(f"invalid temporal input: {exc}")
                if assets is None:
                    from modules.adversarial_self_assessment_v326 import default_personal_surface
                    assets = default_personal_surface()
                out = build_v328_fabric(e.output, target=a.target, assets=assets, chains=chains, timeline=timeline, objective=a.objective)
                print(json.dumps(out, indent=2)); return 0
            elif a.action in {"coverage-assurance", "coverage-assurance-suite"}:
                from modules.universal_coverage_assurance_v332 import build_v332_fabric, v332_test_matrix
                if a.action == "coverage-assurance-suite":
                    out = v332_test_matrix(); print(json.dumps(out, indent=2)); return 0
                observations=[]; completed=[]
                if a.baseline:
                    try:
                        raw=json.loads(Path(a.baseline).read_text(encoding="utf-8"))
                        if isinstance(raw,dict):
                            state=raw.get("canonical_state",raw); observations=state.get("evidence",state.get("observations",[])); completed=state.get("completed",[])
                    except Exception as exc: raise SystemExit(f"invalid coverage input: {exc}")
                out=build_v332_fabric(e.output,target=a.target,objective=a.objective,observations=observations,completed=completed,perspectives=[getattr(a,"perspective","internet_ipv4")])
                print(json.dumps(out, indent=2)); return 0
            elif a.action in {"validation-assurance", "validation-assurance-suite"}:
                from modules.validation_assurance_fabric_v333 import build_v333_fabric, v333_test_matrix
                if a.action == "validation-assurance-suite":
                    out=v333_test_matrix(); print(json.dumps(out, indent=2)); return 0
                raw={}
                if a.baseline:
                    try:
                        raw=json.loads(Path(a.baseline).read_text(encoding="utf-8"))
                        if not isinstance(raw,dict): raise ValueError("baseline must be a JSON object")
                    except Exception as exc: raise SystemExit(f"invalid validation input: {exc}")
                state=raw.get("canonical_state",raw)
                claims=state.get("hypotheses",state.get("claims",[])); evidence=state.get("evidence",[])
                out=build_v333_fabric(e.output,target=a.target,objective=a.objective,claims=claims,evidence=evidence)
                print(json.dumps(out, indent=2)); return 0
            elif a.action in {"evidence-report", "evidence-report-suite"}:
                from modules.evidence_reporting_fabric_v334 import build_v334_fabric, v334_test_matrix
                if a.action == "evidence-report-suite":
                    out=v334_test_matrix(); print(json.dumps(out, indent=2)); return 0
                raw={}
                if a.baseline:
                    try:
                        raw=json.loads(Path(a.baseline).read_text(encoding="utf-8"))
                        if not isinstance(raw,dict): raise ValueError("baseline must be a JSON object")
                    except Exception as exc: raise SystemExit(f"invalid report input: {exc}")
                state=raw.get("canonical_state",raw); validation=raw.get("validation",{})
                out=build_v334_fabric(e.output,target=a.target,objective=a.objective,claims=validation.get("claims",state.get("claims",state.get("hypotheses",[]))),evidence=validation.get("evidence",state.get("evidence",[])),remediation=state.get("remediation",[]),coverage=raw.get("coverage",{}),validation=validation,timeline=state.get("timeline",[]))
                print(json.dumps(out, indent=2)); return 0
            elif a.action in {"engine-self-security", "engine-self-security-suite"}:
                from modules.engine_self_security_v335 import build_v335_fabric, v335_test_matrix
                if a.action == "engine-self-security-suite":
                    out=v335_test_matrix(); print(json.dumps(out, indent=2)); return 0
                out=build_v335_fabric(e.output, repo_root=_REPO_ROOT)
                print(json.dumps(out, indent=2)); return 0
            elif a.action in {"capability-benchmark", "capability-benchmark-suite"}:
                from modules.capability_benchmark_v336 import build_v336_fabric, v336_test_matrix
                if a.action == "capability-benchmark-suite":
                    out=v336_test_matrix(); print(json.dumps(out, indent=2)); return 0
                out=build_v336_fabric(e.output, objective=a.objective)
                print(json.dumps(out, indent=2)); return 0
            elif a.action == "unified-specialist-adapters":
                out = SecurityPlatform(e).unified_specialist_adapters(objective=a.objective)
                print(json.dumps(out, indent=2)); return 0
            elif a.action == "web-api-assurance":
                from modules.web_api_assurance_v338 import build_v338_fabric, v338_test_matrix
                if a.input == "--suite":
                    out=v338_test_matrix()
                else:
                    out=build_v338_fabric(e.output, target=a.target, objective=a.objective)
                print(json.dumps(out, indent=2)); return 0
            elif a.action == "fuzz-campaign":
                out = SecurityPlatform(e).fuzz_campaign_fabric()
                print(json.dumps(out, indent=2)); return 0
            elif a.action == "engagement-datastore":
                out = SecurityPlatform(e).engagement_datastore()
                print(json.dumps(out, indent=2)); return 0
            elif a.action == "identity-assurance":
                out = SecurityPlatform(e).identity_assurance()
                print(json.dumps(out, indent=2)); return 0
            elif a.action in {"capability-closure", "capability-closure-suite"}:
                if a.action == "capability-closure-suite":
                    from modules.capability_closure_fabric_v342 import v342_test_matrix
                    out = v342_test_matrix()
                else:
                    out = SecurityPlatform(e).capability_closure(objective=a.objective)
                print(json.dumps(out, indent=2)); return 0
            elif a.action in {"complete-testing-lab", "complete-testing-lab-suite"}:
                from modules.complete_testing_lab_v343 import build_complete_lab, v343_test_matrix
                if a.action == "complete-testing-lab-suite":
                    out = v343_test_matrix()
                else:
                    out = build_complete_lab(e.output, target=a.target or "127.0.0.1", authorized=True, objective=a.objective)
                print(json.dumps(out, indent=2)); return 0
            elif a.action == "integration-validation-range":
                out = SecurityPlatform(e).integration_validation_range()
                print(json.dumps(out, indent=2)); return 0
            elif a.action == "integration-validation-campaign":
                out = SecurityPlatform(e).integration_validation_campaign()
                print(json.dumps(out, indent=2)); return 0
            elif a.action == "campaign-quality":
                out = SecurityPlatform(e).campaign_quality()
                print(json.dumps(out, indent=2)); return 0
            elif a.action == "campaign-resilience":
                out = SecurityPlatform(e).campaign_resilience()
            elif a.action == "multi-target-integration":
                out = SecurityPlatform(e).multi_target_integration()
                print(json.dumps(out, indent=2)); return 0
            elif a.action == "multi-target-campaign":
                out = SecurityPlatform(e).multi_target_campaign()
                print(json.dumps(out, indent=2)); return 0
            elif a.action == "multi-target-suite":
                out = SecurityPlatform(e).multi_target_suite()
                print(json.dumps(out, indent=2)); return 0
                print(json.dumps(out, indent=2)); return 0
            elif a.action == "realistic-vulnerability-lab":
                out = SecurityPlatform(e).realistic_vulnerability_lab()
                print(json.dumps(out, indent=2)); return 0
            elif a.action == "realistic-vulnerability-campaign":
                out = SecurityPlatform(e).realistic_vulnerability_campaign()
                print(json.dumps(out, indent=2)); return 0
            elif a.action == "realistic-vulnerability-lab-suite":
                from modules.realistic_vulnerability_lab_v344 import v344_test_matrix
                out = v344_test_matrix()
                print(json.dumps(out, indent=2)); return 0
            elif a.action == "assurance-stack":
                out=SecurityPlatform(e).assurance_stack(objective=a.objective, repo_root=_REPO_ROOT)
                print(json.dumps(out, indent=2)); return 0
            elif a.action in {"reliability-integrity", "reliability-integrity-suite"}:
                from modules.reliability_execution_integrity_v331 import build_v331_fabric, v331_test_matrix
                if a.action == "reliability-integrity-suite":
                    out = v331_test_matrix()
                    print(json.dumps(out, indent=2)); return 0
                raw = {}
                if a.baseline:
                    try:
                        raw = json.loads(Path(a.baseline).read_text(encoding="utf-8"))
                        if not isinstance(raw, dict): raise ValueError("baseline must be a JSON object")
                    except Exception as exc: raise SystemExit(f"invalid reliability input: {exc}")
                state = raw.get("canonical_state", raw)
                out = build_v331_fabric(e.output, target=a.target, objective=a.objective, canonical_state=state,
                    authorized=getattr(a,"authorize",False), execute=getattr(a,"execute",False), scope_locked=True,
                    authorization_current=getattr(a,"authorize",False), max_steps=getattr(a,"max_steps",8),
                    deadline_seconds=getattr(a,"timeout",600), tool_budget=max(1, getattr(a,"max_steps",8) * 10),
                    concurrency=1, operations=state.get("operations", []), failures=state.get("failures", []))
                print(json.dumps(out, indent=2)); return 0
            elif a.action in {"unified-assess", "unified-assess-suite"}:
                from modules.unified_assessment_execution_fabric_v330 import build_v330_fabric, v330_test_matrix
                if a.action == "unified-assess-suite":
                    out = v330_test_matrix()
                    print(json.dumps(out, indent=2)); return 0
                raw = {}
                if a.baseline:
                    try:
                        raw = json.loads(Path(a.baseline).read_text(encoding="utf-8"))
                        if not isinstance(raw, dict): raise ValueError("baseline must be a JSON object")
                    except Exception as exc: raise SystemExit(f"invalid unified assessment input: {exc}")
                state = raw.get("canonical_state", raw)
                out = build_v330_fabric(e.output, target=a.target, objective=a.objective,
                    assets=state.get("assets", []), evidence=state.get("evidence", state.get("observations", [])),
                    hypotheses=raw.get("hypotheses", state.get("hypotheses", [])), perspectives=state.get("perspectives", [getattr(a,"perspective","internet_ipv4")]),
                    timeline=state.get("timeline", []), capabilities=state.get("capabilities", []), completed=state.get("completed", []),
                    failures=state.get("failures", []), remediation=state.get("remediation", []), authorized=getattr(a,"authorize",False),
                    execute=getattr(a,"execute",False), scope_locked=True, authorization_current=getattr(a,"authorize",False), max_steps=getattr(a,"max_steps",8))
                print(json.dumps(out, indent=2)); return 0
            elif a.action in {"adversary-simulation", "adversary-simulation-suite"}:
                from modules.adversary_simulation_planner_v329 import build_v329_fabric, v329_test_matrix
                if a.action == "adversary-simulation-suite":
                    out = v329_test_matrix()
                    print(json.dumps(out, indent=2)); return 0
                assets = None; observations = []; chains = []; timeline = []; perspectives = None
                if a.baseline:
                    try:
                        raw = json.loads(Path(a.baseline).read_text(encoding="utf-8"))
                        if isinstance(raw, dict):
                            assets = raw.get("assets") or raw.get("unified_state", {}).get("assets")
                            observations = raw.get("observations", raw.get("evidence", raw.get("unified_state", {}).get("observations", [])))
                            chains = raw.get("chains", raw.get("attack_paths", raw.get("hypotheses", [])))
                            timeline = raw.get("timeline", raw.get("events", raw.get("unified_state", {}).get("timeline", [])))
                    except Exception as exc: raise SystemExit(f"invalid adversary simulation input: {exc}")
                if assets is None:
                    from modules.adversarial_self_assessment_v326 import default_personal_surface
                    assets = default_personal_surface()
                if getattr(a, "input", ""):
                    perspectives = [x.strip() for x in a.input.split(",") if x.strip()]
                out = build_v329_fabric(e.output, target=a.target, assets=assets, observations=observations, chains=chains, timeline=timeline, perspective=getattr(a, "perspective", "internet_ipv4"), perspectives=perspectives, objective=a.objective, authorized=getattr(a, "authorize", False), execute=getattr(a, "execute", False), max_hypotheses=getattr(a, "max_steps", 20))
                print(json.dumps(out, indent=2)); return 0
            elif a.action in {"self-assessment", "adversarial-matrix", "adversarial-reasoning", "reasoning-suite"}:
                from modules.adversarial_self_assessment_v326 import build_chain_analysis, adversarial_test_matrix
                if a.action == "reasoning-suite":
                    from modules.adversarial_reasoning_v327 import adversarial_reasoning_test_suite
                    out = adversarial_reasoning_test_suite()
                    print(json.dumps(out, indent=2)); return 0
                if a.action == "adversarial-reasoning":
                    from modules.adversarial_reasoning_v327 import build_deep_reasoning
                    assets = None; observations = []
                    if a.baseline:
                        try:
                            raw = json.loads(Path(a.baseline).read_text(encoding="utf-8"))
                            if isinstance(raw, dict):
                                assets = raw.get("assets")
                                observations = raw.get("observations", raw.get("evidence", []))
                            elif isinstance(raw, list): observations = raw
                        except Exception as exc: raise SystemExit(f"invalid reasoning input: {exc}")
                    if assets is None:
                        from modules.adversarial_self_assessment_v326 import default_personal_surface, build_asset_dependency_graph
                        assets = default_personal_surface()
                        graph = build_asset_dependency_graph(assets)
                    else:
                        from modules.adversarial_self_assessment_v326 import build_asset_dependency_graph
                        graph = build_asset_dependency_graph(assets)
                    out = build_deep_reasoning(e.output, target=a.target, assets=assets, observations=observations, dependency_graph=graph, objective=a.objective)
                    print(json.dumps(out, indent=2)); return 0
                if a.action == "adversarial-matrix":
                    out = adversarial_test_matrix()
                else:
                    assets = None
                    observations = []
                    if a.baseline:
                        try:
                            raw = json.loads(Path(a.baseline).read_text(encoding="utf-8"))
                            if isinstance(raw, dict):
                                assets = raw.get("assets")
                                observations = raw.get("observations", raw.get("evidence", []))
                            elif isinstance(raw, list):
                                observations = raw
                        except Exception as exc:
                            raise SystemExit(f"invalid self-assessment input: {exc}")
                    out = build_chain_analysis(e.output, target=a.target, assets=assets, observations=observations, objective=a.objective)
            elif a.action == "execution-graph":
                from modules.universal_execution_graph_v323 import build_execution_graph
                selected = [x.strip() for x in a.input.split(",") if x.strip()] if a.input else None
                observations = []
                if a.baseline:
                    try:
                        raw = json.loads(Path(a.baseline).read_text(encoding="utf-8"))
                        observations = raw if isinstance(raw, list) else raw.get("observations", raw.get("evidence", []))
                    except Exception as exc:
                        raise SystemExit(f"invalid baseline: {exc}")
                from modules.universal_execution_graph_v323 import build_execution_graph, run_execution_graph
                if getattr(a, "execute", False):
                    out = run_execution_graph(e.output, target=a.target, scope_file=e.scope_file, observations=observations, surfaces=selected, perspectives=[getattr(a, "perspective", "internet_ipv4")], authorized=getattr(a, "authorize", False), execute=True, max_iterations=getattr(a, "max_steps", 3), timeout=getattr(a, "timeout", 600), objective=a.objective)
                else:
                    out = build_execution_graph(e.output, target=a.target, observations=observations, surfaces=selected, perspectives=[getattr(a, "perspective", "internet_ipv4")], objective=a.objective, max_candidates=getattr(a, "max_steps", 12))
            elif a.action == "r4-execute":
                from modules.universal_specialist_router_v322 import execute_r4_controlled
                action = a.objective.strip()
                if not action:
                    raise SystemExit("--objective must contain the exact R4 action for r4-execute")
                if not a.roe:
                    raise SystemExit("--roe is required for r4-execute")
                from modules.roe_policy_v18 import ROEPolicy
                roe = ROEPolicy.from_file(a.roe)
                supplied = a.approval_token[0] if a.approval_token else ""
                if "=" not in supplied:
                    raise SystemExit("--approval-token must be request_id=token for r4-execute")
                request_id, token = supplied.split("=", 1)
                if not request_id or not token:
                    raise SystemExit("--approval-token must be request_id=token for r4-execute")
                out = execute_r4_controlled(e.output, target=a.target, scope_file=e.scope_file, action=action, authorized=getattr(a, "authorize", False), roe_permitted=roe.permits(action, target=a.target), approval_token=token, approval_request_id=request_id, perspective=getattr(a, "perspective", "testbed"), internal_target=getattr(a, "input", ""))
            else: out = build_domain_fusion(e.output, a.target, a.objective)
        else:
            out = build_benchmark_metrics(e.output)
        print(json.dumps(out, indent=2)); return 0

    if a.engine == "unified-v53":
        from modules.unified_security_core_v530 import UnifiedCoreV53
        e = _engagement(a)
        eng = UnifiedCoreV53(e.output)
        action = getattr(a, "action", "status")
        auth = bool(getattr(a, "authorize", False))
        if action == "audit":
            out = eng.audit()
        elif action == "mission":
            out = eng.mission(e.target, authorized=auth)
        elif action == "browser":
            out = eng.browser(getattr(a, "url", None) or e.target, authorized=auth)
        elif action == "malware-static":
            out = eng.malware_static(getattr(a, "sample", "") or "")
        elif action == "phishing-sim":
            out = eng.phishing_sim(getattr(a, "org", "lab-org"), getattr(a, "scenario", "credential-awareness"))
        elif action == "adversary":
            out = eng.adversary(e.target)
        elif action == "attack-graph":
            out = eng.attack_graph(e.target)
        elif action == "web-advanced":
            out = eng.web_advanced(getattr(a, "url", None) or e.target, authorized=auth)
        elif action == "command-center":
            out = eng.command_center()
        else:
            out = eng.status()
        print(json.dumps(out, indent=2, default=str)); return 0
    if a.engine == "depth-v52":
        from modules.capability_depth_v520 import DepthEngineV52
        e = _engagement(a)
        eng = DepthEngineV52(e.output, scope_file=getattr(a, "scope", None) or e.scope_file)
        action = getattr(a, "action", "status")
        if action == "run-adapter":
            out = eng.run_adapter(getattr(a, "tool", "nmap"), e.target, authorized=bool(getattr(a, "authorize", False)), dry_run=bool(getattr(a, "dry_run", False)))
        elif action == "import":
            out = eng.import_findings(getattr(a, "import_files", []) or [])
        elif action == "propose":
            out = eng.propose(e.target, provider=getattr(a, "provider", "heuristic"))
        elif action == "snapshot":
            out = eng.snapshot(getattr(a, "snapshot_label", "default"))
        elif action == "diff":
            out = eng.diff(getattr(a, "diff_a", ""), getattr(a, "diff_b", ""))
        elif action == "report":
            out = eng.report(e.target)
        elif action == "benchmark":
            out = eng.benchmark(e.target)
        elif action == "mcp-list":
            out = eng.mcp_list()
        else:
            out = eng.status()
        print(json.dumps(out, indent=2, default=str))
        return 0
    if a.engine == "fusion-v51":
        from modules.capability_fusion_v510 import FusionEngineV51
        e = _engagement(a)
        eng = FusionEngineV51(e.output)
        action = getattr(a, "action", "status")
        installed = [x.strip() for x in str(getattr(a, "installed_tools", "")).split(",") if x.strip()]
        if action == "episode":
            raw = ""
            rf = getattr(a, "raw_output_file", "") or ""
            if rf and Path(rf).is_file():
                raw = Path(rf).read_text(encoding="utf-8", errors="replace")[:200000]
            out = eng.episode(e.target, getattr(a, "objective", "authorized assessment"), installed, raw)
        elif action == "import":
            out = eng.import_findings(getattr(a, "import_files", []) or [])
        elif action == "port-pipeline":
            out = eng.port_pipeline(e.target, installed)
        elif action == "sarif":
            out = eng.sarif_from_imports()
        elif action == "offline-roles":
            out = eng.offline_roles()
        elif action == "register-images":
            out = eng.register_evidence_images(getattr(a, "image_files", []) or [])
        else:
            out = eng.status()
        print(json.dumps(out, indent=2, default=str))
        return
    if a.engine == "fusion":
        e = _engagement(a)
        from modules.ai_capability_fusion_v500 import FusionEngine, MCPBridge
        engine = FusionEngine(e.output)
        if getattr(a, "mcp_list", False):
            out = MCPBridge(engine).handle({"jsonrpc":"2.0","id":1,"method":"tools/list"})
        else:
            out = engine.build(e.target, a.objective, authorized=bool(a.authorize))
        print(json.dumps(out, indent=2)); return 0 if out.get("status") != "blocked" else 2

    if a.engine == "tools":
        from security_platform.core.tools import inventory
        print(json.dumps([x.__dict__ for x in inventory()], indent=2)); return 0

    if a.engine == "cloud":
        e = _engagement(a)
        from modules.cloud_multiplatform_v32 import assess_export, assess_live
        try:
            out = assess_export(e.output, a.provider, a.export) if a.export else assess_live(e.output, a.provider)
        except (OSError, ValueError, RuntimeError) as exc:
            out = {"status":"blocked","reason":str(exc)}
        print(json.dumps(out, indent=2)); return 0 if out.get("status") in {"completed","partial","blocked"} else 2

    if a.engine == "ad-relationships":
        e = _engagement(a)
        from modules.ad_relationships_v32 import analyze
        try: out = analyze(e.output, a.input)
        except (OSError, ValueError, json.JSONDecodeError) as exc: out = {"status":"blocked","reason":str(exc)}
        print(json.dumps(out, indent=2)); return 0 if out.get("status") != "blocked" else 2

    if a.engine == "ios":
        e = _engagement(a)
        from modules.mobile_ios_v32 import analyze_ipa
        out = analyze_ipa(e.output, a.ipa)
        print(json.dumps(out, indent=2)); return 0 if out.get("status") == "completed" else 2

    if a.engine == "ios-dynamic":
        e = _engagement(a)
        if a.allow_launch:
            from modules.security import require_authorization
            require_authorization()
        from modules.mobile_ios_dynamic_v33 import assess_export, inspect_simulator
        out = assess_export(e.output, a.export) if a.export else inspect_simulator(
            e.output, bundle_id=a.bundle_id, device=a.device, allow_launch=a.allow_launch
        )
        print(json.dumps(out, indent=2)); return 0 if out.get("status") == "completed" else 2

    if a.engine == "ble":
        e = _engagement(a)
        from modules.wireless_ble_v32 import assess_export
        out = assess_export(e.output, a.input)
        print(json.dumps(out, indent=2)); return 0 if out.get("status") == "completed" else 2

    if a.engine == "container":
        e = _engagement(a)
        from modules.container_security_v33 import assess_archive
        out = assess_archive(e.output, a.archive)
        print(json.dumps(out, indent=2)); return 0 if out.get("status") == "completed" else 2

    if a.engine == "database":
        e = _engagement(a)
        from modules.database_surface_v33 import assess
        out = assess(e.output, a.input)
        print(json.dumps(out, indent=2)); return 0 if out.get("status") == "completed" else 2

    if a.engine == "network-config":
        e = _engagement(a)
        from modules.network_device_config_v33 import assess
        out = assess(e.output, a.input)
        print(json.dumps(out, indent=2)); return 0 if out.get("status") == "completed" else 2

    if a.engine == "mobile":
        e = _engagement(a)
        if a.dynamic:
            from modules.security import require_authorization
            require_authorization()
        out = MobileEngine(e).android(a.apk, dynamic=a.dynamic, serial=a.serial, allow_physical=a.allow_physical)
        print(json.dumps(out, indent=2)); return 0 if out.get("status") == "completed" else 2

    if a.engine == "wireless":
        e = _engagement(a)
        from modules.security import require_authorization
        require_authorization()
        out = WirelessEngine(e).assess(a.interface, a.pcap)
        print(json.dumps(out, indent=2)); return 0 if out.get("status") in {"completed", "blocked"} else 2

    if a.engine == "remote":
        from modules.roe_policy_v18 import ROEPolicy
        from security_platform.core.preflight import check
        e = _engagement(a)
        if a.execute:
            pf = check(a.target, e.scope_file, active=True)
            if not pf.ready_for_active:
                out = {"status":"blocked", "reason":"preflight-failed", "blockers":list(pf.blockers), "target":a.target}
                print(json.dumps(out, indent=2)); return 2
        roe = ROEPolicy.from_file(a.roe or None)
        permitted = roe.permits("controlled_attack_chain_test", target=a.target)
        out = RemoteEngine(e).assess(tuple(x.strip() for x in a.scenarios.split(",") if x.strip()),
                                     execute=bool(a.execute), authorized=bool(a.authorize),
                                     roe_permitted=permitted, internal_target=a.internal_target)
        print(json.dumps(out, indent=2)); return 0 if out.get("status") in {"completed", "dry_run", "blocked"} else 2

    if a.engine == "attack-chain":
        from modules.roe_policy_v18 import ROEPolicy
        from modules.attack_chain_lab_v20 import run_lab_attack_chain
        e = _engagement(a)
        roe = ROEPolicy.from_file(a.roe)
        permitted = roe.permits("controlled_attack_chain_test", target=a.target)
        out = run_lab_attack_chain(e.output, initial_url=a.target, internal_url=a.internal_target,
                                   authorized=bool(a.authorize), execute=bool(a.execute),
                                   approval_token=a.approval_token, roe_permitted=permitted,
                                   scope_file=e.scope_file)
        print(json.dumps(out, indent=2)); return 0 if out.get("status") in {"completed", "dry_run"} else 2



    if a.engine == "authorized-proof":
        from modules.authorized_exploitation_v31 import run_authorized_proof
        out = Path(a.output_dir).resolve()
        result = run_authorized_proof(
            outdir=out,
            target_url=a.url,
            technique=a.technique,
            scope_file=Path(a.scope).resolve(),
            approved=bool(a.approve_proof),
        )
        print(json.dumps(result, indent=2)); return 0 if result.get("status") in {"executed","blocked"} else 1
    if a.engine == "exploit-playbooks":
        from modules.authorized_exploitation_v31 import generate_authorized_exploit_playbooks
        out = Path(a.output_dir).resolve() / "exploit-playbooks"
        paths = generate_authorized_exploit_playbooks(out)
        print(json.dumps({"status":"ok","files":paths}, indent=2)); return 0


    if a.engine == "high-risk":
        from modules.high_risk_controls_v32 import HighRiskController, MASTER_PHRASE
        from modules.high_risk_executor_v32 import supervised_run
        out = Path(a.output_dir).resolve(); out.mkdir(parents=True, exist_ok=True)
        ctl = HighRiskController(out)
        if a.roe:
            ctl.load_roe(a.roe)
        if a.kill_switch:
            ctl.engage_kill_switch()
            print(json.dumps({"status": "kill_switch_engaged"}, indent=2)); return 0
        if a.clear_kill_switch:
            ok = ctl.clear_kill_switch(master_phrase=a.master_phrase)
            print(json.dumps({"status": "cleared" if ok else "denied"}, indent=2)); return 0 if ok else 2
        if a.status or (not a.enable and not a.disable and not a.run_supervised):
            print(json.dumps(ctl.status(), indent=2)); return 0
        if a.disable:
            ctl.disable_action(a.disable)
            print(json.dumps({"status": "disabled", "action": a.disable}, indent=2)); return 0
        if a.enable:
            result = ctl.enable_action(
                a.enable,
                authorized=bool(a.authorize),
                master_phrase=a.master_phrase,
                action_phrase=a.action_phrase,
            )
            print(json.dumps(result, indent=2)); return 0 if result.get("status") == "enabled" else 2
        if a.run_supervised:
            result = supervised_run(out, a.run_supervised, token=a.token, target=a.target, controller=ctl)
            print(json.dumps(result, indent=2)); return 0 if result.get("status") == "supervised_plan_created" else 2


    if a.engine == "engage":
        from modules.engagement_runner_v33 import EngagementRunner
        out = Path(a.output_dir).resolve()
        executor = None
        if a.execute:
            if not (a.authorize and a.in_scope):
                print(json.dumps({"status":"blocked","reason":"--execute requires --authorize and --in-scope"}, indent=2)); return 2
            from modules.tool_executor import build_executor
            executor = build_executor(out, scope_file=Path(a.scope).resolve())
        runner = EngagementRunner(out, a.target, authorized=bool(a.authorize), in_scope=bool(a.in_scope), dry_run=not bool(a.execute), executor=executor)
        result = runner.run(resume=not bool(a.no_resume))
        print(json.dumps(result, indent=2)); return 0 if result.get("status") == "ok" else 2
    if a.engine == "cockpit":
        from modules.operator_cockpit_v33 import build_cockpit
        out = Path(a.output_dir).resolve()
        print(json.dumps(build_cockpit(out, a.target), indent=2)); return 0
    if a.engine == "lab-cert":
        from modules.lab_certification_v33 import run_lab_cert
        data = run_lab_cert()
        out = Path(getattr(a, "output_dir", "output/lab-cert")).resolve()
        out.mkdir(parents=True, exist_ok=True)
        (out / "lab-cert.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
        print(json.dumps(data, indent=2)); return 0 if data.get("certified") else 1

    if a.engine == "matrix":
        from modules.executable_capability_matrix import write_report
        out = Path(a.output_dir).resolve(); out.mkdir(parents=True, exist_ok=True)
        path = write_report(out / "evidence")
        print(json.dumps({"status": "ok", "path": str(path)}, indent=2)); return 0
    if a.engine == "redteam-support":
        from modules.red_team_support_v30 import generate_red_team_pack
        out = Path(a.output_dir).resolve() / "redteam-support"
        result = generate_red_team_pack(out, domain=getattr(a, "domain", ""), dc_ip=getattr(a, "dc_ip", ""), target=a.target)
        print(json.dumps(result, indent=2)); return 0
    if a.engine == "self-test":
        from modules.adversarial_self_test_v30 import write_report
        out = Path(getattr(a, "output_dir", "output/self-test")).resolve()
        path = write_report(out)
        data = json.loads(path.read_text(encoding="utf-8"))
        print(json.dumps(data, indent=2)); return 0 if data.get("failed", 1) == 0 else 1

    if a.engine == "autonomy":
        from modules.approval_queue import ApprovalQueue
        from modules.autonomy_policy import AutonomyPolicy, ACTION_RISK, RiskClass
        from modules.roe_policy_v18 import ROEPolicy
        e = _engagement(a)
        q = ApprovalQueue(e.output / "evidence")
        if a.list_pending:
            print(json.dumps(q.list_pending(), indent=2)); return 0
        if a.approve:
            token = q.approve(a.approve)
            if not token:
                print(json.dumps({"status":"not_approved","request_id":a.approve}, indent=2)); return 2
            print(json.dumps({"status":"approved","request_id":a.approve,"token":token}, indent=2)); return 0
        if a.deny:
            ok=q.deny(a.deny); print(json.dumps({"status":"denied" if ok else "not_found","request_id":a.deny}, indent=2)); return 0 if ok else 2
        roe=ROEPolicy.from_file(a.roe or None)
        from security_platform.core.preflight import check
        pf=check(a.target, e.scope_file, active=bool(a.execute))
        in_scope=bool(pf.target_in_scope) if a.execute else True
        authorized=bool(a.authorize)
        policy=AutonomyPolicy(profile=a.profile)
        if a.request_action:
            risk=policy.risk_for(a.request_action)
            if risk == RiskClass.R4 and not roe.permits(a.request_action, target=a.target):
                print(json.dumps({"status":"blocked","reason":"ROE does not permit requested R4 action","action":a.request_action}, indent=2)); return 2
            if risk == RiskClass.R5:
                print(json.dumps({"status":"blocked","reason":"R5 action is permanently denied","action":a.request_action}, indent=2)); return 2
            req=q.find_active(a.request_action,a.target) or q.submit(a.request_action,a.target,a.request_reason or "operator-request",risk=risk.value)
            print(json.dumps({"status":"queued","request_id":req.request_id,"risk":risk.value}, indent=2)); return 0
        from modules.autonomous_loop import AutonomousLoop
        loop=AutonomousLoop(e.output,a.target,policy=policy,authorized=authorized,in_scope=in_scope,dry_run=not a.execute,scope_file=e.scope_file,roe=roe)
        out=loop.run(cycles=max(1,min(a.cycles,20)))
        print(json.dumps(out,indent=2)); return 0

    if a.engine == "adaptive":
        e = _engagement(a)
        platform = SecurityPlatform(e)
        out = platform.adaptive_assessment(authorized=bool(a.authorize))
        print(json.dumps(out, indent=2)); return 0

    if a.engine == "investigate":
        e = _engagement(a)
        out = SecurityPlatform(e).adaptive_investigation(authorized=bool(a.authorize), max_iterations=max(1,min(a.iterations,10)))
        print(json.dumps(out, indent=2)); return 0

    if a.engine == "opsec":
        from modules.opsec_v25 import build_posture
        e = _engagement(a)
        out = build_posture(e.output, operator_alias=a.operator_alias)
        print(json.dumps(out, indent=2)); return 0 if out.get("status") in {"completed", "attention"} else 2

    if a.engine == "mission":
        e = _engagement(a)
        from modules.mission_planner_v34 import build
        out = build(e.output, e.target, authorized=bool(a.authorize))
        print(json.dumps(out, indent=2)); return 0

    e = _engagement(a)
    platform = SecurityPlatform(e)
    if a.engine == "pentest":
        try:
            pol = ScopePolicy.from_file(e.scope_file, e.target)
        except ValueError as exc:
            print(json.dumps({"engine":"pentest","status":"blocked","target":e.target,"blockers":[str(exc)]}, indent=2))
            return 2
        out = PentestEngine(e, pol).run(tuple(x.strip() for x in a.phases.split(",") if x.strip()), require_authorization=not getattr(a, "authorize", False), verify_credentials=getattr(a, "verify_credentials", False), credential_id=getattr(a, "credential_id", ""), show_credentials=getattr(a, "show_credentials", False))
    elif a.engine == "osint":
        out = OSINTEngine(e).run(a.objective, a.input, not a.no_public_collection)
    elif a.engine == "bounty":
        if not a.program_policy:
            raise SystemExit("--program-policy is required for bounty mode")
        out = BugBountyEngine(e).intelligence(a.program_name, a.program_policy, a.asset, execute=a.execute, authorized=getattr(a, "authorize", False))
    else:
        names = tuple(x.strip() for x in a.engines.split(",") if x.strip())
        if "bounty" in names and not a.program_policy:
            raise SystemExit("--program-policy is required when platform includes bounty")
        out = platform.run_selected(
            names, pentest_phases=tuple(x.strip() for x in a.phases.split(",") if x.strip()),
            osint_objective=a.objective, osint_inputs=a.input,
            public_osint=not a.no_public_collection,
            bounty_program=a.program_name, bounty_policy=a.program_policy,
            bounty_assets=a.asset, bounty_execute=a.execute, mobile_apk=a.apk, mobile_dynamic=a.mobile_dynamic, mobile_serial=a.mobile_serial, mobile_allow_physical=a.mobile_allow_physical, wireless_interface=a.wireless_interface, wireless_pcap=a.wireless_pcap, remote_scenarios=a.remote_scenarios, remote_internal_target=a.remote_internal_target, remote_execute=a.remote_execute)
    print(json.dumps(out, indent=2)); return 0

if __name__ == "__main__": raise SystemExit(main())
