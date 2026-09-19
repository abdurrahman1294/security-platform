from modules.rare_case_reasoner_v367 import reason, learn_case
from modules.attack_path_intelligence_v367 import build_attack_path
from modules.security_conversation_v367 import SecurityConversation

def test_rare_case_analogies_and_novel_reasoning(tmp_path):
    learn_case(tmp_path,problem="proxy cache and identity mismatch",lesson="Compare trust boundaries before concluding",tags=["proxy"])
    r=reason(root=tmp_path,problem="unusual proxy identity mismatch",story="the behavior only occurs after login")
    assert r["analogous_cases"]
    assert len(r["novel_hypotheses"]) >= 4
    assert r["execution_contract"]["reasoning_only"] is True

def test_attack_path_ranks_candidate(tmp_path):
    r=build_attack_path(target="127.0.0.1",story="numeric ID returns another user's object",findings=[{"title":"IDOR","confidence":.9}])
    assert r["nodes"] and r["edges"] and r["next_paths"]
    assert r["next_paths"][0]["information_gain"] > 0

def test_conversation_persists(tmp_path):
    c=SecurityConversation(tmp_path,target="127.0.0.1",engagement="lab")
    r=c.ask("Is this hackable?")
    assert r["answer"]
    assert (tmp_path/"evidence"/"security-conversation-v367.json").exists()
