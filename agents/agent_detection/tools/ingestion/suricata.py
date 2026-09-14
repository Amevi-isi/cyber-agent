# tools/ingestion/suricata.py

import json
from ..base import BaseTool

class SuricataTool(BaseTool):
    def __init__(self, file_path: str):
        super().__init__("suricata_tool")
        self.file_path = file_path

    def _load_events(self):
        with open(self.file_path, "r", encoding="utf-8") as f:
            content = f.read().strip()

        if not content:
            return []

        # JSON array log file
        if content.lstrip().startswith("["):
            data = json.loads(content)
            return data if isinstance(data, list) else [data]

        # JSONL/line-delimited
        events = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            events.append(json.loads(line))

        return events

    def run(self, limit=None):
        events = self._load_events()
        if limit is None:
            return events
        return events[:limit]