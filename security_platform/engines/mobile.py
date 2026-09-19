from __future__ import annotations
from pathlib import Path
from security_platform.core.engagement import Engagement
from modules.mobile_android_v23 import analyze_apk, dynamic_readonly

class MobileEngine:
    name="mobile"; version="3.2"
    def __init__(self, engagement: Engagement): self.e=engagement
    def ios(self, ipa_path: str):
        from modules.mobile_ios_v32 import analyze_ipa
        return analyze_ipa(self.e.output, ipa_path)

    def ios_dynamic(self, *, bundle_id: str = "", device: str = "booted", export: str = "", allow_launch: bool = False):
        from modules.mobile_ios_dynamic_v33 import assess_export, inspect_simulator
        return assess_export(self.e.output, export) if export else inspect_simulator(
            self.e.output, bundle_id=bundle_id, device=device, allow_launch=allow_launch
        )

    def android(self, apk_path: str, *, dynamic=False, serial="", allow_physical=False):
        result=analyze_apk(self.e.output, apk_path)
        if dynamic and result.get("status")=="completed":
            result["dynamic"]=dynamic_readonly(self.e.output,serial=serial,allow_physical=allow_physical)
        return result
