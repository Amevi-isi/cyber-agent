"""
LLM Orchestrateur SOC — Claude + MCP tool_use

Remplace SOCOrchestrator par un LLM (Claude) qui décide dynamiquement
de l'ordre et des étapes du pipeline en appelant les agents via MCP/SSE.

Architecture:
    [Event] → Claude (tool_use loop)
                  ↓ appel dynamique selon résultats
    ┌─────────────────────────────────────────────────┐
    │ detect_event()          → agent_detection:8001  │
    │ identify_incident()     → agent_identification:8002 │
    │ recommend_containment() → agent_protection:8003  │
    │ execute_response()      → agent_reponse:8004     │
    │ plan_recovery()         → agent_recuperation:8005 │
    └─────────────────────────────────────────────────┘

Usage:
    python llm_orchestrator.py
    # Ou importer LLMOrchestrator et appeler .run(event)

Variables d'environnement:
    ANTHROPIC_API_KEY
    AGENT_DETECTION_URL       (défaut: http://localhost:8001)
    AGENT_IDENTIFICATION_URL  (défaut: http://localhost:8002)
    AGENT_PROTECTION_URL      (défaut: http://localhost:8003)
    AGENT_RESPONSE_URL        (défaut: http://localhost:8004)
    AGENT_RECUPERATION_URL    (défaut: http://localhost:8005)
    AUTO_RESPOND              (défaut: false — passer à true pour exécuter IRIS/MISP/FortiGate)
"""
import asyncio
import json
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

import anthropic
import ollama
from mcp import ClientSession
from mcp.client.sse import sse_client

# ── Endpoints des agents MCP ──────────────────────────────────────────────────
AGENT_URLS: dict[str, str] = {
    "detect_event":           os.getenv("AGENT_DETECTION_URL",      "http://localhost:8001"),
    "identify_incident":      os.getenv("AGENT_IDENTIFICATION_URL",  "http://localhost:8002"),
    "recommend_containment":  os.getenv("AGENT_PROTECTION_URL",     "http://localhost:8003"),
    "execute_response":       os.getenv("AGENT_RESPONSE_URL",       "http://localhost:8004"),
    "plan_recovery":          os.getenv("AGENT_RECUPERATION_URL",   "http://localhost:8005"),
}

# ── Définitions des outils pour Claude ────────────────────────────────────────
TOOL_DEFINITIONS: list[dict] = [
    {
        "name": "detect_event",
        "description": (
            "Stage 1 — NIST Detection. "
            "Analyse un événement de sécurité brut. "
            "Retourne: classification (benign/suspicious/confirmed_incident/unknown), "
            "attack_type, mitre_tactic, mitre_technique, severity, confidence (0-100), iocs, evidence_extract."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "event": {
                    "type": "object",
                    "description": "Événement brut (Suricata, Wazuh, EDR, Fortigate, …)",
                }
            },
            "required": ["event"],
        },
    },
    {
        "name": "identify_incident",
        "description": (
            "Stage 2 — NIST Analysis. "
            "Analyse approfondie d'un incident détecté. "
            "Enrichit les IOCs (GeoIP), construit le profil d'incident, corrèle avec les événements passés. "
            "Retourne: incident_id, threat_actor, scope, victim_assets, attack_chain, enriched_iocs, confidence."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "detection_output": {
                    "type": "object",
                    "description": "Sortie complète de detect_event",
                }
            },
            "required": ["detection_output"],
        },
    },
    {
        "name": "recommend_containment",
        "description": (
            "Stage 3 — NIST Containment. "
            "Génère un plan de confinement précis. "
            "NE EXECUTE PAS les actions. "
            "Retourne: urgency, assets_to_isolate, ips_to_block, accounts_to_disable, containment_summary."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "identification_output": {
                    "type": "object",
                    "description": "Sortie complète de identify_incident",
                }
            },
            "required": ["identification_output"],
        },
    },
    {
        "name": "execute_response",
        "description": (
            "Stage 4 — NIST Eradication/Response. "
            "Exécute les actions de réponse: crée cas IRIS, soumet IOCs MISP, bloque IPs FortiGate. "
            "Retourne: actions_executed, errors, total_success, total_errors."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "protection_output": {
                    "type": "object",
                    "description": "Sortie complète de recommend_containment",
                },
                "identification_output": {
                    "type": "object",
                    "description": "Sortie complète de identify_incident",
                },
            },
            "required": ["protection_output", "identification_output"],
        },
    },
    {
        "name": "plan_recovery",
        "description": (
            "Stage 5 — NIST Recovery + Post-Incident. "
            "Génère le plan de restauration, d'éradication et les leçons apprises. "
            "Retourne: eradication_checklist, recovery_steps, hardening_measures, lessons_learned."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "identification_output": {
                    "type": "object",
                    "description": "Sortie complète de identify_incident",
                },
                "response_report": {
                    "type": "object",
                    "description": "Sortie complète de execute_response",
                },
            },
            "required": ["identification_output", "response_report"],
        },
    },
]

SYSTEM_PROMPT = """You are an autonomous SOC (Security Operations Center) orchestrator.
You manage a cybersecurity incident response pipeline following NIST SP 800-61.

You have 5 specialized agent tools. Based on what each agent returns, you decide the next step.

## PIPELINE ROUTING RULES

1. ALWAYS start with detect_event on the raw event.

2. After detection:
   - classification = "benign" AND severity = "low" → STOP. Log only.
   - classification = "unknown" AND confidence < 30 → STOP. Insufficient data.
   - classification = "suspicious" OR "confirmed_incident" → call identify_incident.

3. After identification:
   - Always call recommend_containment.

4. After containment recommendations:
   - If AUTO_RESPOND=true AND classification = "confirmed_incident" AND severity in (high, critical) AND confidence >= 60:
     → call execute_response.
   - Otherwise: STOP. Present recommendations to analysts.

5. After response execution:
   - Always call plan_recovery.

## OUTPUT

When the pipeline is complete, respond with a concise JSON summary:
{
  "verdict": "classification result",
  "stages_executed": ["detect_event", ...],
  "pipeline_stopped_at": "stage_name or complete",
  "stop_reason": "why pipeline stopped",
  "stages": {
    "detection": {...},
    "identification": {...},
    ...
  }
}

## CONSTRAINTS
- Do NOT skip stages out of order.
- Do NOT execute_response unless severity is high/critical AND confidence >= 60.
- Always explain your routing decision before calling a tool.
"""


def _to_ollama_tools(anthropic_tools: list[dict]) -> list[dict]:
    """Convertit les définitions d'outils Anthropic vers le format Ollama (OpenAI-compatible)."""
    return [
        {
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t["description"],
                "parameters": t["input_schema"],
            },
        }
        for t in anthropic_tools
    ]


async def _call_mcp_agent(tool_name: str, args: dict) -> dict:
    """Appelle un agent MCP via SSE et retourne le résultat désérialisé."""
    agent_url = AGENT_URLS[tool_name]
    sse_url = f"{agent_url}/sse"
    try:
        async with sse_client(url=sse_url) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(tool_name, args)
                if result.content:
                    raw = result.content[0].text
                    try:
                        return json.loads(raw)
                    except json.JSONDecodeError:
                        return {"raw_response": raw}
                return {"error": "empty response from agent"}
    except Exception as exc:
        return {"error": f"MCP call failed for {tool_name}: {exc}"}


class LLMOrchestrator:
    """
    Orchestrateur SOC piloté par LLM.
    Sélectionne automatiquement le backend selon l'environnement :
      - ANTHROPIC_API_KEY défini → Claude (production, tool_use natif)
      - sinon                    → Ollama llama3.2 (dev, 100 % local)
    """

    def __init__(
        self,
        anthropic_api_key: str = None,
        auto_respond: bool = False,
        max_iterations: int = 10,
    ):
        self.auto_respond = auto_respond
        self.max_iterations = max_iterations

        api_key = anthropic_api_key or os.getenv("ANTHROPIC_API_KEY")
        if api_key:
            self._backend = "claude"
            self._claude = anthropic.Anthropic(api_key=api_key)
            print("[LLM_ORCHESTRATOR] Backend: Claude (Anthropic)")
        else:
            self._backend = "ollama"
            self._ollama_model = os.getenv("OLLAMA_MODEL", "llama3.2")
            print(f"[LLM_ORCHESTRATOR] Backend: Ollama ({self._ollama_model})")

    async def run(self, event: dict) -> dict:
        """Exécute le pipeline SOC. Dispatche vers Claude ou Ollama selon le backend."""
        if self._backend == "claude":
            return await self._run_claude(event)
        return await self._run_ollama(event)

    # ── Backend Claude ────────────────────────────────────────────────────────

    async def _run_claude(self, event: dict) -> dict:
        """Pipeline piloté par Claude avec tool_use natif Anthropic."""
        auto_respond_str = "true" if self.auto_respond else "false"
        system = SYSTEM_PROMPT.replace("AUTO_RESPOND=true", f"AUTO_RESPOND={auto_respond_str}")

        messages: list[dict] = [
            {
                "role": "user",
                "content": (
                    f"New security event received. Process it through the SOC pipeline.\n\n"
                    f"Event:\n{json.dumps(event, indent=2)}"
                ),
            }
        ]

        stages: dict = {}
        stages_executed: list[str] = []
        final_response: str = ""

        for iteration in range(self.max_iterations):
            print(f"[LLM_ORCHESTRATOR] Iteration {iteration + 1}...")

            response = self._claude.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=8192,
                system=system,
                tools=TOOL_DEFINITIONS,
                messages=messages,
            )

            messages.append({"role": "assistant", "content": response.content})

            if response.stop_reason == "end_turn":
                for block in response.content:
                    if hasattr(block, "text"):
                        final_response = block.text
                print(f"[LLM_ORCHESTRATOR] Pipeline complete after {iteration + 1} iterations.")
                break

            if response.stop_reason == "tool_use":
                tool_results: list[dict] = []

                for block in response.content:
                    if block.type != "tool_use":
                        continue

                    tool_name = block.name
                    tool_input = block.input
                    print(f"[LLM_ORCHESTRATOR] Calling agent: {tool_name}...")

                    result = await _call_mcp_agent(tool_name, tool_input)
                    stages[tool_name] = result
                    stages_executed.append(tool_name)
                    print(f"[LLM_ORCHESTRATOR] {tool_name} → {list(result.keys())}")

                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": json.dumps(result, ensure_ascii=False),
                    })

                messages.append({"role": "user", "content": tool_results})

        return {
            "event": event,
            "stages_executed": stages_executed,
            "stages": stages,
            "final_analysis": final_response,
            "auto_respond": self.auto_respond,
        }

    # ── Backend Ollama ────────────────────────────────────────────────────────

    async def _run_ollama(self, event: dict) -> dict:
        """Pipeline piloté par Ollama (llama3.1+) avec tool_use format OpenAI-compatible."""
        auto_respond_str = "true" if self.auto_respond else "false"
        system = SYSTEM_PROMPT.replace("AUTO_RESPOND=true", f"AUTO_RESPOND={auto_respond_str}")

        ollama_tools = _to_ollama_tools(TOOL_DEFINITIONS)

        messages: list[dict] = [
            {"role": "system", "content": system},
            {
                "role": "user",
                "content": (
                    f"New security event received. Process it through the SOC pipeline.\n\n"
                    f"Event:\n{json.dumps(event, indent=2)}"
                ),
            },
        ]

        stages: dict = {}
        stages_executed: list[str] = []
        final_response: str = ""

        for iteration in range(self.max_iterations):
            print(f"[LLM_ORCHESTRATOR] Iteration {iteration + 1}...")

            # ollama.chat est synchrone — on l'exécute dans un thread pour ne pas bloquer
            response = await asyncio.to_thread(
                ollama.chat,
                model=self._ollama_model,
                messages=messages,
                tools=ollama_tools,
            )

            # Ajouter la réponse de l'assistant aux messages
            messages.append(response.message)

            if not response.message.tool_calls:
                final_response = response.message.content or ""
                print(f"[LLM_ORCHESTRATOR] Pipeline complete after {iteration + 1} iterations.")
                break

            for tool_call in response.message.tool_calls:
                tool_name = tool_call.function.name
                tool_input = tool_call.function.arguments  # dict déjà parsé
                print(f"[LLM_ORCHESTRATOR] Calling agent: {tool_name}...")

                result = await _call_mcp_agent(tool_name, tool_input)
                stages[tool_name] = result
                stages_executed.append(tool_name)
                print(f"[LLM_ORCHESTRATOR] {tool_name} → {list(result.keys())}")

                messages.append({
                    "role": "tool",
                    "content": json.dumps(result, ensure_ascii=False),
                })

        return {
            "event": event,
            "stages_executed": stages_executed,
            "stages": stages,
            "final_analysis": final_response,
            "auto_respond": self.auto_respond,
        }


# ── Point d'entrée ─────────────────────────────────────────────────────────────
async def _main():
    auto_respond = os.getenv("AUTO_RESPOND", "false").lower() == "true"
    orchestrator = LLMOrchestrator(auto_respond=auto_respond)

    # Événements de test
    events = [
        {
            "source": "wazuh",
            "rule": "multiple failed ssh login",
            "agent": "server1",
            "src_ip": "185.220.101.5",
            "user": "root",
            "timestamp": "2026-04-02T10:23:11Z",
            "attempts": 47,
        },
        {
            "source": "suricata",
            "alert": "ET SCAN Nmap TCP",
            "src_ip": "10.0.0.42",
            "dst_ip": "192.168.1.0/24",
            "timestamp": "2026-04-02T10:25:00Z",
        },
    ]

    results = []
    for event in events:
        print(f"\n{'='*60}")
        print(f"[LLM_ORCHESTRATOR] Processing event from: {event.get('source')}")
        print(f"{'='*60}")
        result = await orchestrator.run(event)
        results.append(result)
        print(f"[LLM_ORCHESTRATOR] Stages executed: {result['stages_executed']}")

    # Écrire le rapport
    output_path = Path(__file__).parent / "pipeline_report.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n[LLM_ORCHESTRATOR] Report written to {output_path}")


if __name__ == "__main__":
    asyncio.run(_main())
