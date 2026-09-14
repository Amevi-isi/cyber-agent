"""
MCP Server — agent_recuperation (NIST: Recovery + Post-Incident)

Expose plan_recovery() comme outil MCP via transport SSE.

Usage:
    python server.py
    # Ou via docker-compose (service agent_recuperation)

Variables d'environnement:
    AGENT_RECUPERATION_PORT : port SSE (défaut: 8005)
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
from agent import RecuperationAgent

# ── Agent setup ───────────────────────────────────────────────────────────────
_memory = Memory()
_llm = build_llm()
_agent = RecuperationAgent(_llm, _memory)

# ── MCP Server ────────────────────────────────────────────────────────────────
mcp = FastMCP("agent_recuperation")


@mcp.tool()
def plan_recovery(identification_output: dict, response_report: dict) -> dict:
    """
    Stage 5 — NIST SP 800-61: Recovery + Post-Incident Activity.

    Génère le plan de restauration complet :
    - Checklist d'éradication (nettoyage des systèmes compromis)
    - Étapes de restauration (sauvegardes, réinitialisation des credentials)
    - Mesures de durcissement post-incident
    - Leçons apprises et recommandations

    Args:
        identification_output: Sortie de identify_incident (agent_identification)
        response_report: Sortie de execute_response (agent_reponse)

    Returns:
        dict: Plan de récupération avec checklists et lessons learned
    """
    return _agent.plan(identification_output, response_report)


if __name__ == "__main__":
    port = int(os.getenv("AGENT_RECUPERATION_PORT", "8005"))
    mcp.run(transport="sse", host="0.0.0.0", port=port)
