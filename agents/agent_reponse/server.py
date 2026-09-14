"""
MCP Server — agent_reponse (NIST: Eradication / Response)

Expose execute_response() comme outil MCP via transport SSE.

Usage:
    python server.py
    # Ou via docker-compose (service agent_reponse)

Variables d'environnement:
    AGENT_RESPONSE_PORT   : port SSE (défaut: 8004)
    IRIS_URL, IRIS_TOKEN
    MISP_URL, MISP_TOKEN
    FORTIGATE_URL, FORTIGATE_TOKEN
    OLLAMA_MODEL, LLM_MAX_TOKENS, LLM_TEMPERATURE
"""
import sys
import importlib.util
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

HERE = Path(__file__).parent
agents_root = HERE.parent
sys.path.insert(0, str(agents_root / "agent_detection"))

from mcp.server.fastmcp import FastMCP
from memory import Memory
from llm import build_llm


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# Chargement isolé pour éviter le conflit namespace tools/
_guards = _load("reponse_guards",   HERE / "guards.py")
sys.modules["guards"] = _guards
_agent_mod = _load("reponse_agent", HERE / "agent.py")
_iris_mod  = _load("reponse_iris",  HERE / "tools" / "iris.py")
_misp_mod  = _load("reponse_misp",  HERE / "tools" / "misp.py")
_fg_mod    = _load("reponse_fg",    HERE / "tools" / "fortigate.py")

ResponseAgent = _agent_mod.ResponseAgent
IRISTool      = _iris_mod.IRISTool
MISPTool      = _misp_mod.MISPTool
FortiGateTool = _fg_mod.FortiGateTool

# ── Agent setup ───────────────────────────────────────────────────────────────
_memory    = Memory()
_llm       = build_llm()
_iris      = IRISTool()
_misp      = MISPTool()
_fortigate = FortiGateTool()
_agent     = ResponseAgent(_llm, _memory, iris=_iris, misp=_misp, fortigate=_fortigate)

# ── MCP Server ────────────────────────────────────────────────────────────────
mcp = FastMCP("agent_reponse")


@mcp.tool()
def execute_response(protection_output: dict, identification_output: dict) -> dict:
    """
    Stage 4 — NIST SP 800-61: Eradication / Response.

    Exécute les actions de réponse concrètes :
    - Crée un cas dans IRIS (DFIR)
    - Soumet les IOCs dans MISP
    - Bloque les IPs sur FortiGate
    Chaque outil est optionnel si non configuré.

    Args:
        protection_output: Sortie de recommend_containment (agent_protection)
        identification_output: Sortie de identify_incident (agent_identification)

    Returns:
        dict: Rapport d'exécution (actions_executed, errors, totaux)
    """
    return _agent.execute(protection_output, identification_output)


if __name__ == "__main__":
    port = int(os.getenv("AGENT_RESPONSE_PORT", "8004"))
    mcp.run(transport="sse", host="0.0.0.0", port=port)
