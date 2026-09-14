"""
MCP Server — agent_identification (NIST: Analysis)

Expose identify_incident() comme outil MCP via transport SSE.

Usage:
    python server.py
    # Ou via docker-compose (service agent_identification)

Variables d'environnement:
    AGENT_IDENTIFICATION_PORT : port SSE (défaut: 8002)
    CHROMA_HOST, CHROMA_PORT, CHROMA_COLLECTION_NAME
    OLLAMA_MODEL, LLM_MAX_TOKENS, LLM_TEMPERATURE
"""
import sys
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

HERE = Path(__file__).parent
agents_root = HERE.parent
sys.path.insert(0, str(agents_root / "agent_detection"))
sys.path.insert(0, str(HERE))

from mcp.server.fastmcp import FastMCP
from memory import ChromaMemory
from llm import build_llm
from tools.enrichment.geoip import GeoIPTool
from agent import IdentificationAgent

# ── Agent setup ───────────────────────────────────────────────────────────────
_memory = ChromaMemory(
    collection_name=os.getenv("CHROMA_COLLECTION_NAME", "soc_events"),
    chroma_host=os.getenv("CHROMA_HOST", "localhost"),
    chroma_port=int(os.getenv("CHROMA_PORT", "8000")),
)
_geoip = GeoIPTool()
_llm = build_llm()
_agent = IdentificationAgent(_llm, _memory, geoip_tool=_geoip)

# ── MCP Server ────────────────────────────────────────────────────────────────
mcp = FastMCP("agent_identification")


@mcp.tool()
def identify_incident(detection_output: dict) -> dict:
    """
    Stage 2 — NIST SP 800-61: Analysis.

    Analyse approfondie d'un incident détecté :
    - Enrichit les IOCs (géolocalisation, réputation)
    - Construit le profil d'incident (threat_actor, scope, timeline)
    - Relie aux événements passés via mémoire sémantique
    - Retourne incident_id, victim_assets, attack_chain, enriched_iocs

    Args:
        detection_output: Sortie de detect_event (agent_detection)

    Returns:
        dict: Profil complet de l'incident
    """
    return _agent.analyze(detection_output)


if __name__ == "__main__":
    port = int(os.getenv("AGENT_IDENTIFICATION_PORT", "8002"))
    mcp.run(transport="sse", host="0.0.0.0", port=port)
