# tools/enrichment/geoip.py

import ipaddress
import requests
from ..base import BaseTool


class GeoIPTool(BaseTool):
    def __init__(self, timeout: int = 5):
        super().__init__("geoip_tool")
        self.timeout = timeout
        self._private_ranges = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("127.0.0.0/8"),
        ]

    def _is_private(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in self._private_ranges)
        except ValueError:
            return False

    def run(self, ip: str) -> dict:
        if self._is_private(ip):
            return {"ip": ip, "type": "private", "country": None, "city": None,
                    "isp": None, "lat": None, "lon": None}
        try:
            response = requests.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,country,regionName,city,isp,lat,lon,query"},
                timeout=self.timeout,
            )
            response.raise_for_status()
            data = response.json()
            if data.get("status") != "success":
                return {"ip": ip, "type": "public", "error": data.get("message", "lookup failed")}
            return {
                "ip": ip,
                "type": "public",
                "country": data.get("country"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "isp": data.get("isp"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
            }
        except requests.RequestException as exc:
            return {"ip": ip, "type": "public", "error": str(exc)}
