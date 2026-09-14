# tools/fortigate.py — Client FortiGate REST API (FortiOS)
import os
import requests


class FortiGateTool:
    """
    Client REST pour FortiGate (FortiOS API v2).

    Variables d'environnement:
        FORTIGATE_URL   : https://fortigate.company.com
        FORTIGATE_TOKEN : <api_key>

    Prérequis FortiGate:
        - Un groupe d'adresses nommé "SOC_BLOCKLIST" doit exister
        - Ce groupe doit être référencé dans une règle de pare-feu de blocage
    """

    def __init__(self, base_url: str = None, api_key: str = None, verify_ssl: bool = False):
        self.base_url = (base_url or os.getenv("FORTIGATE_URL", "")).rstrip("/")
        self.api_key = api_key or os.getenv("FORTIGATE_TOKEN", "")
        self.verify_ssl = verify_ssl
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        })

    def _request(self, method: str, path: str, payload: dict = None) -> dict:
        url = f"{self.base_url}/api/v2/cmdb{path}"
        response = self._session.request(
            method, url, json=payload, verify=self.verify_ssl, timeout=10
        )
        response.raise_for_status()
        return response.json()

    def block_ip(self, ip: str, comment: str = "SOC automated block") -> dict:
        """
        Crée un objet adresse pour l'IP et l'ajoute au groupe SOC_BLOCKLIST.
        Retourne le statut de l'opération.
        """
        addr_name = f"SOC_BLOCK_{ip.replace('.', '_')}"

        # Step 1: Create address object (/32)
        try:
            self._request("POST", "/firewall/address", {
                "name": addr_name,
                "type": "ipmask",
                "subnet": f"{ip}/32",
                "comment": comment,
            })
        except requests.HTTPError as exc:
            if exc.response.status_code != 409:  # 409 = already exists, OK
                raise

        # Step 2: Add to blocklist group
        try:
            self._request("POST", "/firewall/addrgrp/SOC_BLOCKLIST/member", {
                "member": [{"name": addr_name}],
            })
        except requests.HTTPError:
            # Group may not exist — return partial success
            return {"ip": ip, "address_object": addr_name, "status": "address_created_group_missing"}

        return {"ip": ip, "address_object": addr_name, "status": "blocked"}

    def unblock_ip(self, ip: str) -> dict:
        """Supprime l'objet adresse correspondant à l'IP (et le retire du groupe)."""
        addr_name = f"SOC_BLOCK_{ip.replace('.', '_')}"
        self._request("DELETE", f"/firewall/address/{addr_name}")
        return {"ip": ip, "status": "unblocked"}

    def list_blocked_ips(self) -> list:
        """Retourne la liste des membres du groupe SOC_BLOCKLIST."""
        result = self._request("GET", "/firewall/addrgrp/SOC_BLOCKLIST")
        members = result.get("results", [{}])[0].get("member", [])
        return [m["name"].replace("SOC_BLOCK_", "").replace("_", ".") for m in members]
