# tools/misp.py — Client MISP Threat Sharing
import os
import requests


class MISPTool:
    """
    Client REST pour MISP (https://www.misp-project.org/).

    Variables d'environnement:
        MISP_URL   : https://misp.company.com
        MISP_TOKEN : <authkey>
    """

    def __init__(self, base_url: str = None, api_key: str = None, verify_ssl: bool = True):
        self.base_url = (base_url or os.getenv("MISP_URL", "")).rstrip("/")
        self.api_key = api_key or os.getenv("MISP_TOKEN", "")
        self.verify_ssl = verify_ssl
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": self.api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        })

    def _post(self, path: str, payload: dict) -> dict:
        url = f"{self.base_url}{path}"
        response = self._session.post(url, json=payload, verify=self.verify_ssl, timeout=10)
        response.raise_for_status()
        return response.json()

    def create_event(
        self,
        info: str,
        threat_level: int = 2,
        distribution: int = 0,
    ) -> dict:
        """
        Crée un événement MISP.
        threat_level: 1=High, 2=Medium, 3=Low, 4=Undefined
        distribution: 0=Org only, 1=Community, 2=Connected, 3=All
        """
        payload = {
            "Event": {
                "info": info,
                "threat_level_id": threat_level,
                "distribution": distribution,
                "analysis": 0,
            }
        }
        result = self._post("/events", payload)
        return result.get("Event", result)

    def submit_ioc(
        self,
        ioc_type: str,
        value: str,
        comment: str = "",
        event_id: int = None,
    ) -> dict:
        """
        Soumet un IOC dans MISP.
        Crée un événement si event_id non fourni.
        ioc_type: "ip-dst", "ip-src", "domain", "md5", "sha256", "url", etc.
        """
        if event_id is None:
            event = self.create_event(info=f"SOC IOC: {value}")
            event_id = event.get("id")

        payload = {
            "Attribute": {
                "event_id": event_id,
                "type": ioc_type,
                "value": value,
                "comment": comment,
                "to_ids": True,
                "distribution": 0,
            }
        }
        return self._post(f"/events/{event_id}/attributes/add", payload)

    def search_ioc(self, value: str) -> dict:
        """Cherche si un IOC est déjà connu dans MISP."""
        return self._post("/attributes/restSearch", {"value": value})
