# tools/ingestion/wazuh.py

import json
import requests
from ..base import BaseTool

class WazuhTool(BaseTool):
    def __init__(self, source: str, token: str = None, is_file: bool = False):
        super().__init__("wazuh_tool")
        self.source = source
        self.token = token
        self.is_file = is_file

    def _load_events_from_file(self):
        with open(self.source, "r", encoding="utf-8") as f:
            content = f.read().strip()

        if not content:
            return []

        if content.lstrip().startswith("["):
            data = json.loads(content)
            return data if isinstance(data, list) else [data]

        events = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            events.append(json.loads(line))

        return events

    def run(self, query: dict = None, limit: int = None):
        if self.is_file:
            events = self._load_events_from_file()
            if query:
                # query expected as dict of keys to match
                events = [e for e in events if all(e.get(k) == v for k, v in query.items())]
            return events if limit is None else events[:limit]

        url = self.source
        headers = {
            "Authorization": f"Bearer {self.token}"
        }
        response = requests.post(url, json=query, headers=headers)
        return response.json()