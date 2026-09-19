#!/usr/bin/env python3
"""V3.56 one-command complete engine validation campaign.

Runs compilation and the full regression suite, then executes the local
capability, realistic-vulnerability, multi-target integration, specialist-tool integration, evidence normalization, tool-aware planning, quality,
resilience, end-to-end assurance gate, and production self-security checks in-process. All assessment
fixtures are loopback/local and disposable.
"""
from __future__ import annotations
import argparse, json, subprocess, sys, time
from pathlib import Path


def run_process(cmd, cwd, log_dir, timeout=90):
    import hashlib, os, signal
    started=time.time(); log_dir.mkdir(parents=True, exist_ok=True)
    safe_name="_".join(x.replace("/","_").replace("\\","_") for x in cmd[1:4])[:60] + "-" + hashlib.sha256("\x00".join(cmd).encode()).hexdigest()[:12]
    log_path=log_dir/(safe_name+".log")
    with log_path.open("w", encoding="utf-8") as fh:
        proc=subprocess.Popen(cmd,cwd=cwd,text=True,stdout=fh,stderr=subprocess.STDOUT,start_new_session=True)
        try:
            rc=proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try: os.killpg(proc.pid, signal.SIGTERM)
            except Exception: proc.kill()
            try: proc.wait(timeout=5)
            except Exception: proc.kill()
            fh.write(f"\nTIMEOUT after {timeout}s\n")
            rc=124
    return {"command":cmd,"returncode":rc,"duration_s":round(time.time()-started,2),"log":str(log_path)}


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--output-dir',default='./artifacts/complete-test-campaign')
    ap.add_argument('--target',default='127.0.0.1')
    args=ap.parse_args()
    root=Path(__file__).resolve().parents[1]
    if str(root) not in sys.path: sys.path.insert(0, str(root))
    out=(root/args.output_dir).resolve() if not Path(args.output_dir).is_absolute() else Path(args.output_dir).resolve()
    out.mkdir(parents=True,exist_ok=True)
    logs=out/'logs'; results=[]
    from modules.pretest_readiness_v355 import run_pretest_readiness
    readiness=run_pretest_readiness(root, out/'pretest-readiness')
    if readiness.get('status') != 'PASS':
        summary={'schema_version':'3.56.0','campaign':'complete-engine-test-campaign','target':args.target,'pretest_readiness':readiness,'tests':results,'all_commands_passed':False,'aborted_before_tests':True,'completed_at':time.time()}
        (out/'complete-test-campaign-summary.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
        print(json.dumps(summary,indent=2)); return 1
    results.append(run_process([sys.executable,'-m','compileall','-q','modules','security_platform','tests','tools'],root,logs))
    results.append(run_process([sys.executable,'-m','pytest','-q'],root,logs,timeout=180))
    if any(r['returncode'] != 0 for r in results):
        summary={'schema_version':'3.56.0','campaign':'complete-engine-test-campaign','target':args.target,'tests':results,'all_commands_passed':False,'aborted_before_labs':True,'completed_at':time.time()}
        (out/'complete-test-campaign-summary.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
        print(json.dumps(summary,indent=2)); return 1

    from modules.complete_testing_lab_v343 import build_complete_lab, v343_test_matrix
    from modules.realistic_vulnerability_lab_v344 import run_realistic_campaign, v344_test_matrix
    from modules.integration_validation_range_v345 import run_integration_range, v345_test_matrix
    from modules.campaign_quality_resilience_v346 import build_quality_artifact, v346_test_matrix
    from modules.campaign_resilience_v347 import run_resilience_checks, v347_test_matrix
    from modules.multi_target_integration_v348 import run_multi_target_campaign, v348_test_matrix
    from modules.engine_self_security_v335 import build_v335_fabric
    from modules.range_assurance_gate_v349 import build_gate, v349_test_matrix
    from modules.specialist_conformance_v350 import build_conformance, v350_test_matrix
    from modules.specialist_tool_integration_v351 import run_tool_integration, v351_test_matrix
    from modules.tool_evidence_normalization_v352 import v352_test_matrix
    from modules.tool_aware_specialist_planner_v353 import build_plan, v353_test_matrix
    from modules.specialist_isolated_range_v354 import run_specialist_range, v354_test_matrix
    from modules.controlled_proof_fabric_v356 import catalog as v356_catalog, v356_test_matrix

    lab=build_complete_lab(out/'lab',target=args.target,authorized=True,objective='complete-engine-validation')
    realistic=run_realistic_campaign(out/'realistic-vulnerabilities')
    integration=run_integration_range(out/'integration-range')
    quality=build_quality_artifact(out/'campaign-quality',integration)
    resilience=run_resilience_checks(out/'campaign-resilience')
    multi=run_multi_target_campaign(out/'multi-target')
    selfsec=build_v335_fabric(out/'self-security',repo_root=root,include_tests=False)
    gate=build_gate(out/'range-assurance-gate',repo_root=root,multi_report=multi,resilience=resilience)
    conformance=build_conformance(out/'specialist-conformance',repo_root=root)
    tool_integration=run_tool_integration(out/'specialist-tool-integration', execute=True)
    tool_plan=build_plan(out/'tool-aware-plan')
    isolated=run_specialist_range(out/'specialist-isolated-range')
    controlled_proof_catalog=v356_catalog()

    matrices={
        'v343':v343_test_matrix(),'v344':v344_test_matrix(),'v345':v345_test_matrix(),
        'v346':v346_test_matrix(),'v347':v347_test_matrix(),'v348':v348_test_matrix(),'v349':v349_test_matrix(),'v350':v350_test_matrix(),'v351':v351_test_matrix(),'v352':v352_test_matrix(),'v353':v353_test_matrix(),'v354':v354_test_matrix(), 'v356':__import__('modules.controlled_proof_fabric_v356', fromlist=['v356_test_matrix']).v356_test_matrix(),
    }
    (out/'suite-matrices.json').write_text(json.dumps(matrices,indent=2),encoding='utf-8')
    lab_ok=lab.get('summary',{}).get('failed',0)==0 and lab.get('summary',{}).get('errors',0)==0
    realistic_ok=realistic.get('summary',{}).get('misses',0)==0 and realistic.get('summary',{}).get('false_positives',0)==0
    integration_ok=integration.get('summary',{}).get('misses',0)==0 and integration.get('summary',{}).get('false_positives',0)==0
    multi_ok=multi.get('summary',{}).get('misses',0)==0 and multi.get('summary',{}).get('false_positives',0)==0
    selfsec_ok=not any(x.get('severity') in {'critical','high','medium'} for x in selfsec.get('findings',[]))
    gate_ok=gate.get('status') == 'PASS'
    conformance_ok=conformance.get('status') == 'PASS'
    tool_integration_ok=tool_integration.get('status') == 'PASS'
    tool_plan_ok=tool_plan.get('status') == 'PASS' and tool_plan.get('policy',{}).get('planning_only') is True
    isolated_ok=isolated.get('status') == 'PASS' and isolated.get('summary',{}).get('misses') == 0 and isolated.get('summary',{}).get('false_positives') == 0
    controlled_proof_ok=controlled_proof_catalog.get('governance',{}).get('single_use_tokens') is True and not controlled_proof_catalog.get('governance',{}).get('arbitrary_commands', True)
    all_ok=all(r['returncode']==0 for r in results) and lab_ok and realistic_ok and integration_ok and multi_ok and selfsec_ok and gate_ok and conformance_ok and tool_integration_ok and tool_plan_ok and isolated_ok and controlled_proof_ok
    summary={
        'schema_version':'3.56.0','campaign':'complete-engine-test-campaign','target':args.target,
        'tests':results,'pretest_readiness':readiness,'all_commands_passed':all_ok,
        'lab_summary':lab.get('summary',{}),'lab_catalog_count':lab.get('catalog_count',0),
        'realistic_vulnerability_summary':realistic.get('summary',{}),
        'integration_range_summary':integration.get('summary',{}),
        'campaign_quality':quality,'campaign_resilience':resilience,
        'multi_target_summary':multi.get('summary',{}),
        'range_assurance_gate':gate,
        'specialist_conformance':conformance,
        'specialist_tool_integration':tool_integration,
        'tool_aware_specialist_plan':tool_plan,
        'specialist_isolated_range':isolated,
        'controlled_proof_catalog':controlled_proof_catalog,
        'multi_target_count':len(multi.get('targets',{})),
        'self_security_summary':{'files_scanned':selfsec.get('files_scanned',0),'findings':len(selfsec.get('findings',[])),'high_medium_critical':sum(1 for x in selfsec.get('findings',[]) if x.get('severity') in {'critical','high','medium'})},
        'suite_scenario_counts':{k:v.get('scenario_count',0) for k,v in matrices.items()},
        'safety':{'loopback_only':True,'external_targets':False,'synthetic_data_only':True,'no_unrestricted_offensive_runtime':True},
        'completed_at':time.time(),
    }
    (out/'complete-test-campaign-summary.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
    print(json.dumps({'schema_version':summary['schema_version'],'all_commands_passed':summary['all_commands_passed'],'lab_summary':summary['lab_summary'],'realistic_vulnerability_summary':summary['realistic_vulnerability_summary'],'integration_range_summary':summary['integration_range_summary'],'multi_target_summary':summary['multi_target_summary'],'range_assurance_gate':summary['range_assurance_gate'],'specialist_conformance':summary['specialist_conformance'],'self_security_summary':summary['self_security_summary'],'summary_file':str(out/'complete-test-campaign-summary.json')},indent=2))
    return 0 if all_ok else 1

if __name__=='__main__': raise SystemExit(main())
