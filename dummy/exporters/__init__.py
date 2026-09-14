import json
import os
from pathlib import Path
from typing import List, Dict, Any


class JSONExporter:
    """Export data to JSON format."""

    def __init__(self, output_dir: str = "dummy/data"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export(self, data: List[Dict], filename: str):
        """Export data to JSON file."""
        filepath = self.output_dir / filename
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"Exported to {filepath}")
        return filepath


class JSONLExporter:
    """Export data to JSON Lines format."""

    def __init__(self, output_dir: str = "dummy/data"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export(self, data: List[Dict], filename: str):
        """Export data to JSONL file."""
        filepath = self.output_dir / filename
        with open(filepath, 'w', encoding='utf-8') as f:
            for item in data:
                f.write(json.dumps(item, ensure_ascii=False) + "\n")
        print(f"Exported to {filepath}")
        return filepath
