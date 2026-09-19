from pathlib import Path
from modules.capability_closure_fabric_v342 import (
    build_v342_fabric, build_capability_closure, simulate_dangerous_capability,
    DANGEROUS, v342_test_matrix,
)


def test_every_taxonomy_entry_has_contract(tmp_path):
    out=build_v342_fabric(tmp_path,target='lab.test')
    assert out['schema_version']=='3.42.0'
    assert out['capability_count'] == sum(len(v) for v in __import__('modules.capability_closure_fabric_v342', fromlist=['CAPABILITY_FAMILIES']).CAPABILITY_FAMILIES.values())
    assert out['closure']['all_taxonomy_entries_have_contract'] is True
    assert (tmp_path/'evidence'/'capability-closure-v342.json').exists()


def test_dangerous_capabilities_are_lab_enveloped(tmp_path):
    rows=build_capability_closure()
    danger=[r for r in rows if r['capability'] in DANGEROUS]
    assert danger
    assert all(r['lab_only'] for r in danger)
    assert all(r['execution_mode']=='deterministic-lab-simulation' for r in danger)
    blocked=simulate_dangerous_capability(tmp_path, capability=next(iter(DANGEROUS)), target='lab.test', approved=False)
    assert blocked['status']=='blocked'


def test_dangerous_simulation_is_synthetic_and_side_effect_free(tmp_path):
    cap=sorted(DANGEROUS)[0]
    out=simulate_dangerous_capability(tmp_path, capability=cap, target='127.0.0.1', approved=True)
    assert out['status']=='simulated'
    assert out['synthetic_evidence']['secrets_collected'] is False
    assert out['synthetic_evidence']['external_side_effects'] is False
    assert out['limitations']


def test_suite_is_comprehensive():
    suite=v342_test_matrix()
    assert suite['scenario_count'] >= 40
