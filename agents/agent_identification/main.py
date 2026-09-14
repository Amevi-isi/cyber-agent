import sys
import os
import json
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

# Shared tools from agent_detection (inserted AFTER current dir)
agents_root = Path(__file__).parent.parent
sys.path.insert(0, str(agents_root / "agent_detection"))
sys.path.insert(0, str(Path(__file__).parent))  # agent_identification en priorité

from memory import Memory, ChromaMemory
from llm import build_llm
from tools.enrichment.geoip import GeoIPTool
from agent import IdentificationAgent

# ── Setup ─────────────────────────────────────────────────────────────────────
# Note: ChromaMemory se connecte à l'instance Docker ChromaDB via HttpClient (pas de stockage local)
# Configuration via .env: CHROMA_HOST (défaut: localhost), CHROMA_PORT (défaut: 8000)
llm = build_llm()
memory = ChromaMemory(
    collection_name=os.getenv("CHROMA_COLLECTION_NAME", "soc_events"),
    k=5,
    chroma_host=os.getenv("CHROMA_HOST", "localhost"),
    chroma_port=int(os.getenv("CHROMA_PORT", "8000")),
)
geoip = GeoIPTool()
agent = IdentificationAgent(llm, memory, geoip_tool=geoip)

# ── Test: feed a detection output ────────────────────────────────────────────
detection_output = {
    "classification": "confirmed_incident",
    "attack_type": "brute_force",
    "mitre_tactic": "TA0006",
    "mitre_technique": "T1110",
    "severity": "high",
    "confidence": 85,
    "event_type": "login",
    "affected_asset": "server1",
    "event_time": "2026-04-02T10:23:11Z",
    "iocs": {
        "ip": ["185.220.101.5"],
        "domain": [],
        "hash": [],
        "user": ["root"]
    },
    "evidence_extract": "47 failed SSH login attempts from 185.220.101.5 targeting server1"
}

result = agent.analyze(detection_output)

if __name__ == "__main__":
    output_path = Path(__file__).parent / "identification_report.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"Rapport écrit dans {output_path}")