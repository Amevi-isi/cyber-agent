"""
MCP Server — agent_detection (NIST: Detection)

Expose detect_event() comme outil MCP via transport SSE.

Usage:
    python server.py
    # Ou via docker-compose (service agent_detection)

Variables d'environnement:
    AGENT_DETECTION_PORT  : port SSE (défaut: 8001)
    CHROMA_HOST, CHROMA_PORT, CHROMA_COLLECTION_NAME
    NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD
    OLLAMA_MODEL, LLM_MAX_TOKENS, LLM_TEMPERATURE
"""
import sys
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

from mcp.server.fastmcp import FastMCP
from memory import ChromaMemory
from llm import build_llm
from agent import DetectionAgent
from tools.correlation.ne4j import Neo4jTool

# ── Agent setup ───────────────────────────────────────────────────────────────
_memory = ChromaMemory(
    collection_name=os.getenv("CHROMA_COLLECTION_NAME", "soc_events"),
    chroma_host=os.getenv("CHROMA_HOST", "localhost"),
    chroma_port=int(os.getenv("CHROMA_PORT", "8000")),
)
_neo4j = Neo4jTool(
    uri=os.getenv("NEO4J_URI", "bolt://localhost:7687"),
    user=os.getenv("NEO4J_USER", "neo4j"),
    password=os.getenv("NEO4J_PASSWORD", "testpassword"),
)
_llm = build_llm()
_agent = DetectionAgent(_llm, _memory, neo4j_tool=_neo4j)

# ── MCP Server ────────────────────────────────────────────────────────────────
mcp = FastMCP("agent_detection")


@mcp.tool()
def detect_event(event: dict) -> dict:
    """
    Stage 1 — NIST SP 800-61: Detection.

    Analyse un événement de sécurité brut et retourne :
    - classification (benign / suspicious / confirmed_incident / unknown)
    - attack_type, mitre_tactic, mitre_technique
    - severity (low / medium / high / critical)
    - confidence (0-100)
    - iocs (ip, domain, hash, user)
    - evidence_extract

    Args:
        event: Événement brut (Suricata, Wazuh, EDR, …)

    Returns:
        dict: Analyse structurée de l'événement
    """
    return _agent.analyze_event_detect(event)


if __name__ == "__main__":
    port = int(os.getenv("AGENT_DETECTION_PORT", "8001"))
    mcp.run(transport="sse", host="0.0.0.0", port=port)
