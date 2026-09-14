import json
import os
from guards import sanitize_identification_output, validate_output, with_timeout, extract_json

LLM_TIMEOUT_SECONDS = int(os.getenv("LLM_TIMEOUT_SECONDS", "120"))


class ProtectionAgent:
    """
    NIST SP 800-61 Phase: Containment
    Génère des recommandations de confinement précises à partir du profil d'incident.
    Ne EXECUTE PAS les actions — c'est agent_reponse qui s'en charge.
    """

    def __init__(self, llm, memory):
        self.llm = llm
        self.memory = memory

    def recommend(self, identification_output: dict) -> dict:
        """
        Prend l'output de agent_identification et produit un plan de confinement.
        Retourne un dict structuré avec les actions recommandées.
        """
        # Guard 1 : input — injection + troncature
        try:
            identification_output = sanitize_identification_output(identification_output)
        except ValueError as exc:
            return {"_guard_input_error": str(exc), "urgency": "unknown", "containment_summary": "blocked"}

        context = self.memory.get_context()

        prompt = f"""You are a cybersecurity containment specialist in a SOC.

Your role is CONTAINMENT PLANNING ONLY.
You generate precise, actionable containment recommendations.
You do NOT execute them — that is handled by the response agent.

## INPUT

Incident analysis:
{json.dumps(identification_output, indent=2)}

Previous context:
{context}

---

## TASKS

1. Identify assets to ISOLATE immediately via EDR (give exact hostnames/IPs).
2. Generate FIREWALL RULES to block malicious IPs/domains identified in the incident.
3. Identify NETWORK SEGMENTS to isolate if lateral movement is suspected.
4. Recommend ACCOUNT ACTIONS (disable users, force password reset) with exact usernames.
5. Suggest MONITORING RULES to add (SIEM/IDS signatures to tune).
6. Assess URGENCY: immediate / scheduled / monitor-only.

## CONSTRAINTS

- Only generate actions directly supported by the incident evidence
- Be specific: give exact IPs, usernames, hostnames to act on
- Do NOT generate speculative rules (e.g., "block all unknown IPs")
- Prioritize by impact — highest risk assets first
- If no action is needed for a category, return an empty list

## OUTPUT FORMAT (STRICT JSON ONLY)

{{
  "urgency": "",
  "firewall_rules": [
    {{
      "action": "block",
      "direction": "inbound",
      "src_ip": "",
      "dst_port": null,
      "protocol": "any",
      "reason": ""
    }}
  ],
  "edr_actions": [
    {{
      "action": "isolate",
      "asset": "",
      "reason": ""
    }}
  ],
  "account_actions": [
    {{
      "action": "disable",
      "user": "",
      "reason": ""
    }}
  ],
  "network_segments_to_block": [],
  "monitoring_rules": [],
  "containment_summary": ""
}}"""

        # Guard 2 : timeout
        timed_ask = with_timeout(LLM_TIMEOUT_SECONDS)(self.llm.ask)
        try:
            result = timed_ask(prompt)
        except TimeoutError as exc:
            return {"_guard_timeout_error": str(exc), "urgency": "unknown", "containment_summary": "timeout"}

        self.memory.add_event(identification_output)

        # Extraire et parser le JSON
        try:
            parsed = extract_json(result)
        except Exception:
            return {"raw": result, "_parse_error": True}

        # Guard 3 : validation du schema de sortie
        return validate_output(parsed)
