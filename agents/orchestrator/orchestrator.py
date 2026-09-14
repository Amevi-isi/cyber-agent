import json
from guards import sanitize_event, validate_pipeline_report

class SOCOrchestrator:
    """
    Orchestrateur central du SOC.
    Reçoit un événement brut et pilote le pipeline complet :
    detection → identification → protection → [reponse → recuperation]

    Routing logic:
    - benign / unknown + low severity  → s'arrête après detection (log only)
    - suspicious / confirmed_incident  → identification + protection
    - confirmed_incident + high/critical + confidence ≥ 60 + auto_respond → reponse + recuperation
    """

    def __init__(
        self,
        detection_agent,
        identification_agent,
        protection_agent,
        response_agent,
        recuperation_agent,
        auto_respond: bool = False,
    ):
        self.detection = detection_agent
        self.identification = identification_agent
        self.protection = protection_agent
        self.response = response_agent
        self.recuperation = recuperation_agent
        self.auto_respond = auto_respond

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _should_escalate(detection: dict) -> bool:
        """Escalade si l'événement est suspect ou confirmé."""
        return detection.get("classification") in ("suspicious", "confirmed_incident")

    @staticmethod
    def _should_respond(detection: dict) -> bool:
        """Réponse active si incident confirmé, sévère et confiant."""
        return (
            detection.get("classification") == "confirmed_incident"
            and detection.get("severity") in ("high", "critical")
            and int(detection.get("confidence", 0)) >= 60
        )

    # ── Main pipeline ──────────────────────────────────────────────────────────

    def process(self, event: dict) -> dict:
        """
        Exécute le pipeline SOC complet sur un événement brut.
        Retourne un rapport structuré avec toutes les étapes exécutées.
        """
        report = {
            "event": event,
            "stages": {},
            "pipeline_stopped_at": None,
            "verdict": "unknown",
        }

        # Guard : input — injection + troncature
        try:
            event = sanitize_event(event)
        except ValueError as exc:
            report["verdict"] = "blocked"
            report["pipeline_stopped_at"] = "input_guard"
            report["_guard_input_error"] = str(exc)
            return validate_pipeline_report(report)

        # ── Stage 1: Detection ────────────────────────────────────────────────────
        print("[ORCHESTRATOR] Stage 1: Detection...")
        detection_output = self.detection.analyze_event_detect(event)
        report["stages"]["detection"] = detection_output

        if not self._should_escalate(detection_output):
            report["verdict"] = detection_output.get("classification", "unknown")
            report["pipeline_stopped_at"] = "detection"
            print(f"[ORCHESTRATOR] Pipeline stopped: {report['verdict']} — no escalation needed.")
            return report

        # ── Stage 2: Identification ────────────────────────────────────────────
        print("[ORCHESTRATOR] Stage 2: Identification...")
        identification_output = self.identification.analyze(detection_output)
        report["stages"]["identification"] = identification_output

        # ── Stage 3: Protection ────────────────────────────────────────────────────
        print("[ORCHESTRATOR] Stage 3: Protection...")
        protection_output = self.protection.recommend(identification_output)
        report["stages"]["protection"] = protection_output

        # ── Stage 4 & 5: Response + Recovery (if authorized) ──────────────────
        if self.auto_respond and self._should_respond(detection_output):
            print("[ORCHESTRATOR] Stage 4: Response (auto_respond=True)...")
            response_report = self.response.execute(protection_output, identification_output)
            report["stages"]["response"] = response_report

            print("[ORCHESTRATOR] Stage 5: Recovery...")
            recuperation_output = self.recuperation.plan(identification_output, response_report)
            report["stages"]["recuperation"] = recuperation_output
        else:
            report["response_note"] = (
                "Stages 4/5 not executed. "
                "Set auto_respond=True or trigger agent_reponse/agent_recuperation manually."
            )

        report["verdict"] = detection_output.get("classification", "unknown")
        report["pipeline_stopped_at"] = "complete"
        return validate_pipeline_report(report)
