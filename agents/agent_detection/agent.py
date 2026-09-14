import json
import os
from guards import sanitize_event, validate_output, with_timeout, extract_json

def _get_timeout() -> int:
    return int(os.getenv("LLM_TIMEOUT_SECONDS", "120"))


class DetectionAgent:
    """NIST SP 800-61 Phase: Detection
    Agent for detecting and analyzing security events from logs/alerts.
    Outputs are fed to agent_identification for deeper analysis."""

    def __init__(self, llm, memory, neo4j_tool=None):

        self.llm = llm
        self.memory = memory
        self.neo4j_tool = neo4j_tool

    def analyze_event(self, event):

        context = self.memory.get_context()

        prompt = f"""
            ou are a SOC detection agent following NIST SP 800-61 
            (Computer Security Incident Handling Guide) and NIST 800-53 (Security and Privacy Controls).

            Event: {event}
            Previous events: {context}

           Input:
            - event (source system, timestamp, host, user, network, signature/rule, metadata)
            - history (previous events, known context, threat intelligence)

            Tasks:
            1. Classify the event: benign / suspicious / confirmed incident / unknown.
            2. Map to ATT&CK technique (if malicious/suspicious).
            3. Identify severity: low / medium / high / critical.
            4. Recommend next actions (NIST playbook style):
            - Detect: what to monitor, rules to tune.
            - Analyze: what data to collect for scope/impact.
            - Contain: quick mitigation steps.
            - Eradicate/Recover: follow-up actions.
            5. Output JSON with fields:
            - classification
            - attack_type
            - mitre_tactic
            - severity
            - confidence (0-100)
            - recommended_steps (list)
            - evidence_extract (short)

            Be concise but informative. Focus on actionable intelligence for SOC analysts.
            Respond only in valid JSON.
            """

        result = self.llm.ask(prompt)

        self.memory.add_event(event)

        return result
    
    def analyze_event_detect(self, event):

        # Guard 1 : input — injection + troncature (avant d'envoyer au LLM)
        try:
            event = sanitize_event(event)
        except ValueError as exc:
            return {"_guard_input_error": str(exc), "classification": "unknown", "severity": "unknown", "confidence": 0}

        context = self.memory.get_context(str(event))

        # Enrichissement Neo4j : contexte graphe sur les entités de l'événement
        neo4j_context = ""
        if self.neo4j_tool:
            try:
                graph_ctx = self.neo4j_tool.get_event_context(event)
                neo4j_context = json.dumps(graph_ctx, indent=2, default=str)
            except Exception as exc:
                neo4j_context = f"(Neo4j unavailable: {exc})"

        prompt = f"""
            You are a cybersecurity detection agent operating in a SOC (Security Operations Center) environment.

            Your role is strictly limited to DETECTION and ANALYSIS.
            You must NOT perform or recommend containment, eradication, or recovery actions.
            Those tasks are handled by other specialized agents.

            ## Graph Intelligence (Neo4j)
            {neo4j_context if neo4j_context else "No graph context available."}

            ## Similar past events (ChromaDB semantic memory)
            {context if context else "No similar past events."}

            ## New event
            {event}
            ---

            ## OBJECTIVE

            Given a security event (logs, alerts, or telemetry), analyze it and produce a structured JSON output.

            ---

            ## TASKS

            1. Classify the event into one of:

            * benign
            * suspicious
            * confirmed_incident
            * unknown (use this if information is insufficient)

            2. Identify the attack type (e.g., brute force, phishing, privilege escalation, malware, etc.)

            * If not applicable, set to "none"

            3. Map the activity to MITRE ATT&CK:

            * Provide:

                * mitre_tactic (e.g., TA0006)
                * mitre_technique (e.g., T1110)
            * If unclear, set both to "unknown"
            * Do NOT guess mappings

            4. Determine severity:

            * low
            * medium
            * high
            * critical

            5. Assign a confidence score (0–100):

            * Based only on available evidence
            * Lower confidence if data is incomplete or ambiguous

            6. Extract key indicators of compromise (IOCs), if present:

            * IP addresses
            * Domains
            * File hashes
            * Usernames

            7. Identify:

            * event_type (login, network, process, file, etc.)
            * affected_asset (hostname, IP, user, service, etc.)
            * event_time (if available)

            8. Provide a short evidence summary:

            * Include only facts from the input
            * Do NOT invent details

            ---

            ## CONSTRAINTS

            * Do NOT recommend actions (no containment, no mitigation, no recovery)
            * Do NOT speculate beyond the given data
            * If uncertain → use "unknown"
            * Be precise and conservative

            ---

            ## OUTPUT FORMAT (STRICT JSON ONLY)

            {{
            "classification": "",
            "attack_type": "",
            "mitre_tactic": "",
            "mitre_technique": "",
            "severity": "",
            "confidence": 0,
            "event_type": "",
            "affected_asset": "",
            "event_time": "",
            "iocs": {{
                "ip": [],
                "domain": [],
                "hash": [],
                "user": []
                }},
            "evidence_extract": ""
            }}

            
            """

        # Guard 2 : timeout sur l'appel LLM
        timed_ask = with_timeout(_get_timeout())(self.llm.ask)
        try:
            result = timed_ask(prompt)
        except TimeoutError as exc:
            return {"_guard_timeout_error": str(exc), "classification": "unknown", "severity": "unknown", "confidence": 0}

        self.memory.add_event(event)

        # Extraire et parser le JSON depuis la réponse brute du LLM
        try:
            parsed = extract_json(result)
        except Exception:
            return {"raw": result, "_parse_error": True}

        # Si le LLM retourne une liste, prendre le premier élément dict
        if isinstance(parsed, list):
            dicts = [item for item in parsed if isinstance(item, dict)]
            if not dicts:
                return {"raw": result, "_parse_error": True}
            parsed = dicts[0]

        if not isinstance(parsed, dict):
            return {"raw": result, "_parse_error": True}

        # Guard 3 : validation du schema de sortie
        return validate_output(parsed)