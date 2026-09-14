# tools/iris.py — Client DFIR-IRIS
import os
import requests


class IRISTool:
    """
    Client REST pour DFIR-IRIS (https://dfir-iris.org/).

    Variables d'environnement:
        IRIS_URL   : https://iris.company.com
        IRIS_TOKEN : <api_key>
    """

    def __init__(self, base_url: str = None, api_key: str = None, verify_ssl: bool = True):
        self.base_url = (base_url or os.getenv("IRIS_URL", "")).rstrip("/")
        self.api_key = api_key or os.getenv("IRIS_TOKEN", "")
        self.verify_ssl = verify_ssl
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        })

    def _post(self, path: str, payload: dict) -> dict:
        url = f"{self.base_url}{path}"
        response = self._session.post(url, json=payload, verify=self.verify_ssl, timeout=10)
        response.raise_for_status()
        return response.json()

    def create_case(
        self,
        title: str,
        description: str,
        severity: int = 2,
        iocs: dict = None,
    ) -> dict:
        """Crée un cas dans IRIS et y attache les IOCs."""
        payload = {
            "case_name": title,
            "case_description": description,
            "case_severity_id": severity,
            "case_customer": 1,
        }
        result = self._post("/api/v1/cases/add", payload)
        case_id = result.get("data", {}).get("case_id")

        if case_id and iocs:
            for ip_data in iocs.get("ip", []):
                ip_val = ip_data.get("value") or ip_data.get("ip") if isinstance(ip_data, dict) else ip_data
                if ip_val:
                    self._add_ioc(case_id, "ip-dst", ip_val)
            for domain in iocs.get("domain", []):
                if domain:
                    self._add_ioc(case_id, "domain", domain)
            for file_hash in iocs.get("hash", []):
                if file_hash:
                    self._add_ioc(case_id, "md5", file_hash)

        return result

    def create_alert(
        self,
        title: str,
        description: str,
        severity: int = 2,
        source: str = "SOC Agent",
    ) -> dict:
        """Crée une alerte dans IRIS."""
        payload = {
            "alert_title": title,
            "alert_description": description,
            "alert_severity_id": severity,
            "alert_source": source,
            "alert_source_event_time": None,
            "alert_status_id": 2,
            "alert_customer_id": 1,
        }
        return self._post("/api/v1/alerts/add", payload)

    def _add_ioc(self, case_id: int, ioc_type: str, value: str) -> dict:
        payload = {
            "ioc_type": ioc_type,
            "ioc_value": value,
            "ioc_tlp_id": 2,
            "ioc_description": "Added by SOC agent",
        }
        return self._post(f"/api/v1/cases/{case_id}/ioc/add", payload)
