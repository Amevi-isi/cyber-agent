import sys
import os
import json
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

agents_root = Path(__file__).parent.parent
sys.path.insert(0, str(agents_root / "agent_detection"))
sys.path.insert(0, str(Path(__file__).parent))  # agent_protection en priorité

from memory import Memory
from llm import build_llm
from agent import ProtectionAgent

# ── Setup ──────────────────────────────────────────────────────────────────────
llm = build_llm()
memory = Memory()
agent = ProtectionAgent(llm, memory)

# ── Test: feed an identification output ───────────────────────────────────────
identification_output = {
    "incident_id": "INC-AUTO",
    "threat_actor": "unknown",
    "scope": "contained",
    "attack_chain": ["reconnaissance", "credential_access"],
    "victim_assets": ["server1", "root"],
    "timeline": [{"time": "2026-04-02T10:23:11Z", "event": "47 failed SSH attempts"}],
    "enriched_iocs": {
        "ip": [{"ip": "185.220.101.5", "type": "public", "country": "Germany",
                "city": "Frankfurt", "isp": "Tor Exit Node"}],
        "domain": [],
        "hash": [],
        "user": ["root"]
    },
    "related_events": [],
    "confidence": 85,
    "analysis_summary": "Brute force SSH attack from Tor exit node 185.220.101.5 targeting root on server1."
}

result = agent.recommend(identification_output)

if __name__ == "__main__":
    output_path = Path(__file__).parent / "protection_report.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"Rapport écrit dans {output_path}")
