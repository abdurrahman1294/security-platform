from __future__ import annotations
from pathlib import Path
from security_platform.core.engagement import Engagement
from modules.remote_lab_v24 import assess

class RemoteEngine:
    name = "remote"
    version = "3.2"
    def __init__(self, engagement: Engagement): self.e = engagement
    def assess(self, scenarios=(), *, execute=False, authorized=False, roe_permitted=False, internal_target=""):
        return assess(self.e.output, self.e.target, scenarios=scenarios, authorized=authorized,
                      execute=execute, roe_permitted=roe_permitted, internal_target=internal_target)
