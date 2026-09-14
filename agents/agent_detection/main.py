import os
import json
from pathlib import Path
from dotenv import load_dotenv

# load_dotenv DOIT être appelé avant tout import de module qui lit os.getenv au niveau module
load_dotenv(Path(__file__).resolve().parents[2] / ".env")

from memory import Memory, ChromaMemory
from llm import build_llm
from agent import DetectionAgent
from tools.correlation.ne4j import Neo4jTool

# ChromaMemory se connecte à l'instance Docker ChromaDB via HttpClient
memory = ChromaMemory(
    collection_name=os.getenv("CHROMA_COLLECTION_NAME", "soc_events"),
    chroma_host=os.getenv("CHROMA_HOST", "localhost"),
    chroma_port=int(os.getenv("CHROMA_PORT", "8000")),
)

neo4j = Neo4jTool(
    uri=os.getenv("NEO4J_URI", "bolt://localhost:7687"),
    user=os.getenv("NEO4J_USER", "neo4j"),
    password=os.getenv("NEO4J_PASSWORD", "testpassword"),
)

llm = build_llm()

agent = DetectionAgent(llm, memory, neo4j_tool=neo4j)

events = [
    {
        "source": "suricata",
        "alert": "ET SCAN Nmap",
        "src_ip": "192.168.1.15",
        "severity": 2
    },
    {
        "source": "wazuh",
        "rule": "multiple failed ssh login",
        "agent": "server1"
    },
]

results = []
for event in events:
    result = agent.analyze_event_detect(event)
    results.append(result)

if __name__ == "__main__":
    output_path = Path(__file__).parent / "soc_report.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"Rapport écrit dans {output_path}")