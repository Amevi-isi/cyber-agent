# tools/enrichment/ioc.py

from ..base import BaseTool

class IOCEnrichmentTool(BaseTool):
    def __init__(self):
        super().__init__("ioc_enrichment")

    def run(self, ioc: str):
        # mock (remplace par VirusTotal plus tard)
        if ioc.startswith("192.168"):
            return {"reputation": "internal"}
        return {"reputation": "unknown"}