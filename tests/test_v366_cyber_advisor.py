from modules.cyber_advisor_v366 import advise

def test_advisor_feasibility_and_decision_framework(tmp_path):
    r=advise(question="Is an IDOR in this API hackable and which way is better?",target="127.0.0.1",root=tmp_path)
    assert r["result"]["topics"]
    assert r["result"]["answer"]
    assert r["result"]["decision_framework"]
    assert r["execution_contract"]["advice_only"] is True
    assert list((tmp_path/"evidence").glob("cyber-advice-v366-*.json"))

def test_advisor_empty_question_rejected():
    try:
        advise(question="   ")
        assert False
    except ValueError:
        assert True
