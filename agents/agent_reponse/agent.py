import json
from guards import sanitize_input, validate_report

class ResponseAgent:
    """
    NIST SP 800-61 Phase: Eradication / Response
    Exécute les actions de réponse concrètes:
    - Crée des cas/alertes dans IRIS (DFIR)
    - Soumet les IOCs dans MISP
    - Bloque les IPs sur FortiGate
    Chaque outil est optionnel (None si non configuré).
    """

    def __init__(self, llm, memory, iris=None, misp=None, fortigate=None):
        self.llm = llm
        self.memory = memory
        self.iris = iris
        self.misp = misp
        self.fortigate = fortigate

    def execute(self, protection_output: dict, identification_output: dict) -> dict:
        """
        Exécute les actions de réponse basées sur les recommandations de protection.
        Retourne un rapport d'exécution structuré.
        """
        # Guard 1 : input — injection + troncature
        try:
            protection_output = sanitize_input(protection_output, "protection_output")
            identification_output = sanitize_input(identification_output, "identification_output")
        except ValueError as exc:
            return {"_guard_input_error": str(exc), "actions_executed": [], "errors": [], "total_success": 0, "total_errors": 0}

        actions_executed = []
        errors = []

        # ── 1. IRIS: Create case ───────────────────────────────────────────────
        if self.iris:
            try:
                iris_result = self.iris.create_case(
                    title=f"SOC Incident — {identification_output.get('threat_actor', 'Unknown Threat')}",
                    description=identification_output.get("analysis_summary", ""),
                    severity=self._map_severity(identification_output.get("confidence", 0)),
                    iocs=identification_output.get("enriched_iocs", {}),
                )
                actions_executed.append({
                    "tool": "iris",
                    "action": "create_case",
                    "status": "success",
                    "result": iris_result,
                })
            except Exception as exc:
                errors.append({"tool": "iris", "action": "create_case", "error": str(exc)})

        # ── 2. MISP: Submit public IOCs ────────────────────────────────────────
        if self.misp:
            iocs = identification_output.get("enriched_iocs", {})
            for ip_data in iocs.get("ip", []):
                ip = ip_data.get("value") or ip_data.get("ip") if isinstance(ip_data, dict) else ip_data
                if ip and (not isinstance(ip_data, dict) or ip_data.get("type") != "private"):
                    try:
                        misp_result = self.misp.submit_ioc(
                            ioc_type="ip-dst",
                            value=ip,
                            comment=identification_output.get("analysis_summary", ""),
                        )
                        actions_executed.append({
                            "tool": "misp",
                            "action": "submit_ioc",
                            "status": "success",
                            "ip": ip,
                            "result": misp_result,
                        })
                    except Exception as exc:
                        errors.append({"tool": "misp", "action": "submit_ioc", "ip": ip, "error": str(exc)})

            for domain in iocs.get("domain", []):
                if domain:
                    try:
                        misp_result = self.misp.submit_ioc(
                            ioc_type="domain",
                            value=domain,
                            comment=identification_output.get("analysis_summary", ""),
                        )
                        actions_executed.append({
                            "tool": "misp",
                            "action": "submit_ioc",
                            "status": "success",
                            "domain": domain,
                            "result": misp_result,
                        })
                    except Exception as exc:
                        errors.append({"tool": "misp", "action": "submit_ioc", "domain": domain, "error": str(exc)})

        # ── 3. FortiGate: Block IPs from firewall rules ────────────────────────
        if self.fortigate:
            for rule in protection_output.get("firewall_rules", []):
                ip = rule.get("src_ip")
                if ip:
                    try:
                        fg_result = self.fortigate.block_ip(
                            ip=ip,
                            comment=rule.get("reason", "SOC automated block"),
                        )
                        actions_executed.append({
                            "tool": "fortigate",
                            "action": "block_ip",
                            "status": "success",
                            "ip": ip,
                            "result": fg_result,
                        })
                    except Exception as exc:
                        errors.append({"tool": "fortigate", "action": "block_ip", "ip": ip, "error": str(exc)})

        report = {
            "actions_executed": actions_executed,
            "errors": errors,
            "total_success": len(actions_executed),
            "total_errors": len(errors),
        }
        self.memory.add_event({"type": "response_report", **report})
        # Guard 2 : validation du rapport de sortie
        return validate_report(report)

    @staticmethod
    def _map_severity(confidence: int) -> int:
        """Mappe confidence 0-100 vers IRIS severity_id 1-4."""
        if confidence >= 80:
            return 4  # critical
        if confidence >= 60:
            return 3  # high
        if confidence >= 40:
            return 2  # medium
        return 1  # low
