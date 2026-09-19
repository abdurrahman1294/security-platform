from pathlib import Path
from modules.specialist_reasoning_loop_v369 import run_loop
import modules.specialist_reasoning_loop_v369 as loop_mod

class BadEngine:
    class X:
        target='127.0.0.1'; output=Path('/tmp/v375-test')
    e=X()
    def probe(self): return {'returncode': 1, 'stderr': 'No input provided'}
    def web(self): return {'status':'failed','reason':'synthetic-no-evidence'}
    def api(self): return {'status':'skipped','reason':'no-url'}


def test_nonzero_returncode_is_not_completed(tmp_path):
    BadEngine.e.output=tmp_path
    out=run_loop(engine=BadEngine(), objective='web', authorized=True, max_rounds=1, max_specialists=1)
    actions=[a for r in out['rounds'] for a in r['actions']]
    probe=[a for a in actions if a['phase']=='probe'][0]
    assert probe['status']=='failed'
    assert probe['evidence_produced'] is False


def test_cross_checks_do_not_claim_corroboration_without_two_successful_domains(tmp_path):
    BadEngine.e.output=tmp_path
    out=run_loop(engine=BadEngine(), objective='web API', story='role behavior', authorized=True, max_rounds=1, max_specialists=4)
    checks=[c for r in out['rounds'] for c in r['cross_checks']]
    assert all(c['status'] != 'corroborated' for c in checks)
    assert all(c['corroboration_claim'] is False for c in checks)


def test_information_gain_is_zero_without_evidence(tmp_path):
    BadEngine.e.output=tmp_path
    original=loop_mod.select_specialists
    loop_mod.select_specialists=lambda **kwargs: [{'specialist':'web','score':1.0,'signals':['web']}]
    try:
        out=run_loop(engine=BadEngine(), objective='web', authorized=True, max_rounds=1, max_specialists=1)
    finally:
        loop_mod.select_specialists=original
    assert out['rounds'][0]['information_gain'] == 0.0
