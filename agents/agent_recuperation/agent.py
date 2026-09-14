import json
import os
from guards import sanitize_input, validate_output, with_timeout, extract_json

LLM_TIMEOUT_SECONDS = int(os.getenv("LLM_TIMEOUT_SECONDS", "120"))


class RecuperationAgent:
    """
    NIST SP 800-61 Phase: Recovery + Post-Incident Activity
    Génère le plan de restauration, les étapes d'éradication,
    et les leçons apprises à partir du rapport de réponse.
    """

    def __init__(self, llm, memory):
        self.llm = llm
        self.memory = memory

    def plan(self, identification_output: dict, response_report: dict) -> dict:
        """
        Génère un plan de récupération complet.
        Retourne un dict structuré avec checklists et leçons apprises.
        """
        # Guard 1 : input — injection + troncature
        try:
            identification_output = sanitize_input(identification_output, "identification_output")
            response_report = sanitize_input(response_report, "response_report")
        except ValueError as exc:
            return {"_guard_input_error": str(exc), "recovery_summary": "blocked"}

        context = self.memory.get_context()

        prompt = f"""You are a cybersecurity recovery specialist in a SOC.

Your role is POST-INCIDENT RECOVERY planning.
Based on the incident analysis and the response actions already executed,
generate a comprehensive recovery plan and lessons learned document.

## INPUT

Incident analysis:
{json.dumps(identification_output, indent=2)}

Response actions executed:
{json.dumps(response_report, indent=2)}

Previous context:
{context}

---

## TASKS

1. Restoration checklist: ordered steps to restore affected systems/services to normal operation.
2. Eradication steps: how to ensure the threat is fully removed from all affected assets.
3. Verification steps: how to confirm systems are clean and fully operational before closing.
4. Monitoring recommendations: what to watch post-recovery (duration, rules, thresholds).
5. Estimated recovery time (ERT) per asset.
6. Lessons learned: what worked, what failed, concrete improvements for the future.

## CONSTRAINTS

- Be specific: reference exact assets, users, and services from the incident
- Prioritize safety: all verification must happen before declaring recovery complete
- Do NOT suggest undoing response actions (firewall blocks, account disables) until verified clean
- Format checklists as ordered steps with a "verified" field set to false
- If recovery time is unknown, use "TBD"

## OUTPUT FORMAT (STRICT JSON ONLY)

{{
  "restoration_checklist": [
    {{
      "step": 1,
      "action": "",
      "asset": "",
      "responsible": "SOC",
      "verified": false
    }}
  ],
  "eradication_steps": [],
  "verification_steps": [],
  "monitoring_recommendations": [
    {{
      "rule": "",
      "duration": "",
      "threshold": ""
    }}
  ],
  "estimated_recovery_time": {{
    "total": "",
    "by_asset": [
      {{"asset": "", "ert": ""}}
    ]
  }},
  "lessons_learned": {{
    "what_worked": [],
    "what_failed": [],
    "improvements": []
  }},
  "recovery_summary": ""
}}"""

        # Guard 2 : timeout
        timed_ask = with_timeout(LLM_TIMEOUT_SECONDS)(self.llm.ask)
        try:
            result = timed_ask(prompt)
        except TimeoutError as exc:
            return {"_guard_timeout_error": str(exc), "recovery_summary": "timeout"}

        self.memory.add_event({
            "type": "recovery_plan",
            "incident_id": identification_output.get("incident_id", "unknown"),
        })

        # Extraire et parser le JSON
        try:
            parsed = extract_json(result)
        except Exception:
            return {"raw": result, "_parse_error": True}

        # Guard 3 : validation du schema de sortie
        return validate_output(parsed)
