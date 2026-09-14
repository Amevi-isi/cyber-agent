import sys
import os
import json
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

agents_root = Path(__file__).parent.parent
sys.path.insert(0, str(agents_root / "agent_detection"))
sys.path.insert(0, str(Path(__file__).parent))  # agent_recuperation en priorité

from memory import Memory
from llm import build_llm
from agent import RecuperationAgent

# ── Setup ──────────────────────────────────────────────────────────────────────
llm = build_llm()
memory = Memory()
agent = RecuperationAgent(llm, memory)

# ── Test ───────────────────────────────────────────────────────────────────────
identification_output = {
    "incident_id": "INC-AUTO",
    "threat_actor": "unknown",
    "scope": "contained",
    "victim_assets": ["server1", "root"],
    "analysis_summary": "Brute force SSH depuis Tor exit node 185.220.101.5 ciblant root@server1.",
    "confidence": 85,
}

response_report = {
    "actions_executed": [
        {"tool": "iris", "action": "create_case", "status": "success"},
        {"tool": "fortigate", "action": "block_ip", "status": "success", "ip": "185.220.101.5"},
    ],
    "errors": [],
    "total_success": 2,
    "total_errors": 0,
}

result = agent.plan(identification_output, response_report)

if __name__ == "__main__":
    output_path = Path(__file__).parent / "recuperation_report.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"Rapport écrit dans {output_path}")
