from pathlib import Path
from modules.tri_modal_assessment_v364 import load_operator_story, collect_observations


def test_operator_story_is_preserved():
    assert "admin endpoint" in load_operator_story(story="I found an admin endpoint")


def test_observation_collector_reads_json(tmp_path):
    (tmp_path/"evidence").mkdir()
    (tmp_path/"evidence"/"x.json").write_text('{"ok":true}')
    out=collect_observations(tmp_path)
    assert out[0]["artifact"] == "x.json"
