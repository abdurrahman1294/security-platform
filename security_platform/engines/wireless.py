from __future__ import annotations
from security_platform.core.engagement import Engagement
from modules.wireless_v23 import inventory, analyze_pcap

class WirelessEngine:
    name="wireless"; version="3.2"
    def __init__(self, engagement: Engagement): self.e=engagement
    def ble(self, scan_export: str):
        from modules.wireless_ble_v32 import assess_export
        return assess_export(self.e.output, scan_export)

    def assess(self, interface="", pcap=""):
        out=inventory(self.e.output,interface)
        if pcap: out["pcap_analysis"]=analyze_pcap(self.e.output,pcap)
        return out
