"""
MCP Server — agent_protection (NIST: Containment)

Expose recommend_containment() comme outil MCP via transport SSE.

Usage:
    python server.py
    # Ou via docker-compose (service agent_protection)

Variables d'environnement:
    AGENT_PROTECTION_PORT : port SSE (défaut: 8003)
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
from memory import Memory
from llm import build_llm
from agent import ProtectionAgent

# ── Agent setup ───────────────────────────────────────────────────────────────
_memory = Memory()
_llm = build_llm()
_agent = ProtectionAgent(_llm, _memory)

# ── MCP Server ────────────────────────────────────────────────────────────────
mcp = FastMCP("agent_protection")


@mcp.tool()
def recommend_containment(identification_output: dict) -> dict:
    """
    Stage 3 — NIST SP 800-61: Containment.

    Génère un plan de confinement précis basé sur le profil d'incident :
    - Actifs à isoler immédiatement (EDR)
    - Règles firewall à appliquer (IP/domaines à bloquer)
    - Comptes à désactiver
    - Urgency (immediate / within_1h / within_24h)
    NE EXECUTE PAS les actions — c'est agent_reponse qui s'en charge.

    Args:
        identification_output: Sortie de identify_incident (agent_identification)

    Returns:
        dict: Plan de confinement structuré
    """
    return _agent.recommend(identification_output)


if __name__ == "__main__":
    port = int(os.getenv("AGENT_PROTECTION_PORT", "8003"))
    mcp.run(transport="sse", host="0.0.0.0", port=port)
