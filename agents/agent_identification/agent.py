import json
import os
from guards import sanitize_detection_output, validate_output, with_timeout, extract_json

LLM_TIMEOUT_SECONDS = int(os.getenv("LLM_TIMEOUT_SECONDS", "120"))


class IdentificationAgent:
    """
    NIST SP 800-61 Phase: Analysis
    Prend l'output de agent_detection, enrichit les IOCs,
    corrèle les événements passés et construit un profil d'incident complet.
    """

    def __init__(self, llm, memory, geoip_tool=None):
        self.llm = llm
        self.memory = memory
        self.geoip = geoip_tool

    def _enrich_ips(self, iocs: dict) -> list:
        if not self.geoip:
            return [{"ip": ip, "note": "geoip_not_configured"} for ip in iocs.get("ip", [])]
        enriched = []
        for ip in iocs.get("ip", []):
            geo = self.geoip.run(ip)
            enriched.append(geo)
        return enriched

    def analyze(self, detection_output: dict) -> dict:
        """
        Analyse complète d'un incident à partir de l'output de agent_detection.
        Retourne un dict structuré avec le profil de l'incident.
        """
        # Guard 1 : input — injection + troncature
        try:
            detection_output = sanitize_detection_output(detection_output)
        except ValueError as exc:
            return {"_guard_input_error": str(exc), "incident_id": "INC-BLOCKED", "scope": "unknown", "confidence": 0}

        enriched_ips = self._enrich_ips(detection_output.get("iocs", {}))

        query = " ".join(filter(None, [
            detection_output.get("attack_type", ""),
            detection_output.get("mitre_technique", ""),
            detection_output.get("evidence_extract", ""),
        ]))
        context = self.memory.get_context(query if query.strip() else None)

        prompt = f"""You are a cybersecurity incident analysis agent operating in a SOC.

Your role is ANALYSIS ONLY — you identify the full scope of an incident.
You do NOT recommend defensive actions. Those are handled by other agents.

## INPUT

Detection output:
{json.dumps(detection_output, indent=2)}

Enriched IPs (GeoIP):
{json.dumps(enriched_ips, indent=2)}

Related past events (semantic search):
{context}

---

## TASKS

1. Build the attack chain: ordered steps of the attack from available evidence.
2. Identify ALL victim assets (hosts, users, services, IPs).
3. Estimate scope: contained / spreading / unknown.
4. Assign a threat actor profile (APT group, script kiddie, insider, unknown).
5. Build a timeline of events (use event_time if available, else mark as unknown).
6. Compile enriched IOCs using the GeoIP data provided above.
7. Reference any related past incidents from the context section.

## CONSTRAINTS

- Only use facts from the input — do NOT invent details
- Do NOT recommend containment or response actions
- If uncertain → use "unknown"
- Be precise and conservative

## OUTPUT FORMAT (STRICT JSON ONLY)

{{
  "incident_id": "INC-AUTO",
  "threat_actor": "",
  "scope": "",
  "attack_chain": [],
  "victim_assets": [],
  "timeline": [],
  "enriched_iocs": {{
    "ip": [],
    "domain": [],
    "hash": [],
    "user": []
  }},
  "related_events": [],
  "confidence": 0,
  "analysis_summary": ""
}}"""

        # Guard 2 : timeout
        timed_ask = with_timeout(LLM_TIMEOUT_SECONDS)(self.llm.ask)
        try:
            result = timed_ask(prompt)
        except TimeoutError as exc:
            return {"_guard_timeout_error": str(exc), "incident_id": "INC-TIMEOUT", "scope": "unknown", "confidence": 0}

        self.memory.add_event(detection_output)

        # Extraire et parser le JSON
        try:
            parsed = extract_json(result)
        except Exception:
            return {"raw": result, "_parse_error": True}

        # Guard 3 : validation du schema de sortie
        return validate_output(parsed)
