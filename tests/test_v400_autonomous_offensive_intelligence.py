from pathlib import Path
from modules.autonomous_offensive_intelligence_v400 import build


def test_v400_unresolved_hypothesis_blocks_premature_convergence(tmp_path):
    ev=tmp_path/"evidence"; ev.mkdir()
    loop={"rounds":[{"actions":[{"phase":"probe","status":"completed","execution_status":"completed","evidence_produced":True,"evidence_artifacts":["probe.json"]}]}]}
    (ev/"probe.json").write_text('{"ok":true}')
    s=build(root=tmp_path,client="c",target="t",scope="s",objective="x",story="API returns different data for two roles and object ids change",loop_result=loop)
    assert s["status"] in {"blocked_pending_evidence","ready_for_operator"}
    assert s["hypotheses"]
    assert s["decision"]["finding_claims"] == "none without verified evidence"


def test_v400_attack_chain_is_planning_only(tmp_path):
    (tmp_path/"evidence").mkdir()
    s=build(root=tmp_path,client="c",target="t",scope="s",objective="x",story="role object id",loop_result={"rounds":[]})
    assert s["attack_chain"]["chains"]
    assert s["governance"]["no_arbitrary_shell"]
    assert all(x["stop_if_unverified"] for x in s["attack_chain"]["chains"])


def test_v400_evidence_does_not_equal_finding(tmp_path):
    ev=tmp_path/"evidence"; ev.mkdir(); (ev/"proof.json").write_text('{"evidence":true}')
    s=build(root=tmp_path,client="c",target="t",scope="s",objective="x",story="web",loop_result={"rounds":[]})
    assert s["decision"]["finding_claims"] == "none without verified evidence"
