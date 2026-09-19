import json
from pathlib import Path
from modules.platform_observability_v171 import build as b171
from modules.execution_scheduler_v172 import build as b172
from modules.config_validation_v173 import build as b173
from modules.osint_source_quality_v174 import build as b174
from modules.osint_entity_resolution_v175 import build as b175
from modules.image_osint_pipeline_v176 import inspect_image
from modules.location_osint_v177 import build as b177
from modules.attack_surface_baseline_v178 import build as b178
from modules.change_analysis_v179 import build as b179
from modules.evidence_chain_v180 import build as b180
from modules.finding_confidence_v181 import build as b181
from modules.report_quality_v182 import build as b182
from modules.compliance_mapping_v183 import build as b183
from modules.plugin_sdk_v184 import build as b184
from modules.worker_readiness_v185 import build as b185
from modules.learning_feedback_v186 import build as b186
from modules.quality_gate_v188 import build as b188
from modules.operator_readiness_v189 import build as b189
from modules.pretest_manifest_v190 import build as b190

def test_excellence_stack(tmp_path):
    from modules.platform_observability_v171 import build as b171
    from modules.execution_scheduler_v172 import build as b172
    from modules.config_validation_v173 import build as b173
    from modules.osint_source_quality_v174 import build as b174
    from modules.osint_entity_resolution_v175 import build as b175
    from modules.attack_surface_baseline_v178 import build as b178
    from modules.change_analysis_v179 import build as b179
    from modules.evidence_chain_v180 import build as b180
    from modules.finding_confidence_v181 import build as b181
    from modules.report_quality_v182 import build as b182
    from modules.compliance_mapping_v183 import build as b183
    from modules.plugin_sdk_v184 import build as b184
    from modules.worker_readiness_v185 import build as b185
    from modules.learning_feedback_v186 import build as b186
    from modules.quality_gate_v188 import build as b188
    from modules.operator_readiness_v189 import build as b189
    from modules.pretest_manifest_v190 import build as b190
    (tmp_path/'evidence').mkdir(); (tmp_path/'reports').mkdir()
    inspect_image('',tmp_path)
    for fn in (b171,b172,b173,b174,b175,b178,b179,b180,b181,b182,b183,b184,b185,b186,b188,b189,b190):
        fn(tmp_path)
    assert (tmp_path/'evidence'/'pretest-manifest-v190.json').exists()
    assert json.loads((tmp_path/'evidence'/'pretest-manifest-v190.json').read_text())['schema_version']=='190.0'
    assert 'no covert tracking' in json.loads((tmp_path/'evidence'/'operator-readiness-v189.json').read_text())['autonomy_limits']
