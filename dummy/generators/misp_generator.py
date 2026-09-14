import random
import string
from datetime import datetime, timedelta
from .base_generator import BaseGenerator


class MISPGenerator(BaseGenerator):
    """Generator for MISP (Malware Information Sharing Platform) IOCs."""

    def __init__(self, config: dict = None):
        super().__init__(config)
        self.malware_families = []
        self.threat_actors = []
        self._load_misc()

    def _load_misc(self):
        """Load miscellaneous data."""
        misc = self.get_dict("malware_families", [])
        self.malware_families = misc
        
    def _generate_hash(self, length: int = 32) -> str:
        """Generate random hash."""
        return ''.join(random.choices(string.hexdigits.lower(), k=length))

    def generate_ioc(self, timestamp: str = None, ioc_type: str = None) -> dict:
        """Generate a single MISP IOC."""
        if timestamp is None:
            timestamp = self.random_timestamp()

        if ioc_type:
            return self._generate_ioc_by_type(timestamp, ioc_type)
        
        return self._generate_random_ioc(timestamp)

    def _generate_ioc_by_type(self, timestamp: str, ioc_type: str) -> dict:
        """Generate IOC by specific type."""
        event_id = random.randint(10000, 99999)
        
        if ioc_type == "ip":
            return self._generate_ip_ioc(event_id, timestamp)
        elif ioc_type == "domain":
            return self._generate_domain_ioc(event_id, timestamp)
        elif ioc_type == "url":
            return self._generate_url_ioc(event_id, timestamp)
        elif ioc_type == "hash":
            return self._generate_hash_ioc(event_id, timestamp)
        
        return self._generate_random_ioc(timestamp)

    def _generate_ip_ioc(self, event_id: int, timestamp: str) -> dict:
        """Generate IP IOC."""
        return {
            "Event": {
                "id": event_id,
                "uuid": self.uuid4(),
                "info": f"C2 Infrastructure - {random.choice(['LockBit', 'Emotet', 'TrickBot'])}",
                "threat_level_id": random.choice([1, 2]),
                "analysis": random.choice([0, 1, 2]),
                "date": timestamp[:10],
                "timestamp": int(datetime.fromisoformat(timestamp.replace('Z', '+00:00')).timestamp()),
                "publish_timestamp": int(datetime.fromisoformat(timestamp.replace('Z', '+00:00')).timestamp()),
                "published": True,
                "Org": {"name": random.choice(["CIRCL", "AlienVault", "ThreatFox"])},
                "Orgc": {"name": "ThreatIntelTeam"}
            },
            "Attribute": {
                "id": random.randint(100000, 999999),
                "type": "ip-dst",
                "category": "Network activity",
                "value": random.choice(["185.220.101.42", "185.220.101.50", "45.142.212.100", "91.121.87.10"]),
                "comment": f"C2 server - {random.choice(['LockBit', 'Emotet'])}",
                "to_ids": True,
                "timestamp": int(datetime.fromisoformat(timestamp.replace('Z', '+00:00')).timestamp())
            },
            "Tag": [
                {"name": "tlp:amber"},
                {"name": f"malware:{random.choice(['lockbit', 'emotet', 'trickbot'])}"},
                {"name": "csirt:malware:c2"}
            ]
        }

    def _generate_domain_ioc(self, event_id: int, timestamp: str) -> dict:
        """Generate domain IOC."""
        return {
            "Event": {
                "id": event_id,
                "uuid": self.uuid4(),
                "info": f"Malicious Domain - {random.choice(['phishing', 'c2', 'exfiltration'])}",
                "threat_level_id": random.choice([1, 2, 3]),
                "analysis": random.choice([0, 1, 2]),
                "date": timestamp[:10],
                "timestamp": int(datetime.fromisoformat(timestamp.replace('Z', '+00:00')).timestamp()),
                "publish_timestamp": int(datetime.fromisoformat(timestamp.replace('Z', '+00:00')).timestamp()),
                "published": True,
                "Org": {"name": random.choice(["CIRCL", "AlienVault", "URLhaus"])},
                "Orgc": {"name": "ThreatIntelTeam"}
            },
            "Attribute": {
                "id": random.randint(100000, 999999),
                "type": "domain",
                "category": "Network activity",
                "value": random.choice(["evil-c2.com", "malware-server.net", "phishing-landing.io", "suspicious-domain.xyz"]),
                "comment": f"Malicious domain - {random.choice(['phishing', 'C2'])}",
                "to_ids": True,
                "timestamp": int(datetime.fromisoformat(timestamp.replace('Z', '+00:00')).timestamp())
            },
            "Tag": [
                {"name": "tlp:amber"},
                {"name": f"malware:{random.choice(['lockbit', 'emotet'])}"},
                {"name": "csirt:malware:domain"}
            ]
        }

    def _generate_url_ioc(self, event_id: int, timestamp: str) -> dict:
        """Generate URL IOC."""
        return {
            "Event": {
                "id": event_id,
                "uuid": self.uuid4(),
                "info": "Malware Hosting URL",
                "threat_level_id": 1,
                "analysis": 2,
                "date": timestamp[:10],
                "timestamp": int(datetime.fromisoformat(timestamp.replace('Z', '+00:00')).timestamp()),
                "publish_timestamp": int(datetime.fromisoformat(timestamp.replace('Z', '+00:00')).timestamp()),
                "published": True,
                "Org": {"name": "URLhaus"},
                "Orgc": {"name": "ThreatIntelTeam"}
            },
            "Attribute": {
                "id": random.randint(100000, 999999),
                "type": "url",
                "category": "Payload delivery",
                "value": f"http://{random.choice(['evil-c2.com', 'malware-server.net'])}/downloads/{random.choice(['invoice.exe', 'update.exe'])}",
                "comment": "Malware download URL",
                "to_ids": True,
                "timestamp": int(datetime.fromisoformat(timestamp.replace('Z', '+00:00')).timestamp())
            },
            "Tag": [
                {"name": "tlp:red"},
                {"name": "malware:dropper"}
            ]
        }

    def _generate_hash_ioc(self, event_id: int, timestamp: str) -> dict:
        """Generate file hash IOC."""
        hash_type = random.choice(["md5", "sha256"])
        
        return {
            "Event": {
                "id": event_id,
                "uuid": self.uuid4(),
                "info": f"Malware Sample - {random.choice(['LockBit', 'Emotet', 'TrickBot'])}",
                "threat_level_id": 1,
                "analysis": 2,
                "date": timestamp[:10],
                "timestamp": int(datetime.fromisoformat(timestamp.replace('Z', '+00:00')).timestamp()),
                "publish_timestamp": int(datetime.fromisoformat(timestamp.replace('Z', '+00:00')).timestamp()),
                "published": True,
                "Org": {"name": "MalwareBazaar"},
                "Orgc": {"name": "ThreatIntelTeam"}
            },
            "Attribute": {
                "id": random.randint(100000, 999999),
                "type": hash_type,
                "category": "Payload delivery",
                "value": self._generate_hash(32 if hash_type == "md5" else 64),
                "comment": f"Malware sample - {random.choice(['LockBit', 'Emotet'])}",
                "to_ids": True,
                "timestamp": int(datetime.fromisoformat(timestamp.replace('Z', '+00:00')).timestamp())
            },
            "Tag": [
                {"name": "tlp:red"},
                {"name": f"malware:{random.choice(['lockbit', 'emotet', 'trickbot'])}"}
            ]
        }

    def _generate_random_ioc(self, timestamp: str) -> dict:
        """Generate random IOC."""
        ioc_types = ["ip", "domain", "url", "hash"]
        ioc_type = random.choice(ioc_types)
        event_id = random.randint(10000, 99999)
        
        if ioc_type == "ip":
            return self._generate_ip_ioc(event_id, timestamp)
        elif ioc_type == "domain":
            return self._generate_domain_ioc(event_id, timestamp)
        elif ioc_type == "url":
            return self._generate_url_ioc(event_id, timestamp)
        else:
            return self._generate_hash_ioc(event_id, timestamp)

    def generate_iocs(self, count: int = 1000, start: datetime = None, end: datetime = None) -> list:
        """Generate multiple IOCs."""
        if start is None:
            start = datetime.utcnow() - timedelta(days=30)
        if end is None:
            end = datetime.utcnow()

        iocs = []
        for _ in range(count):
            timestamp = self.random_timestamp(start, end)
            iocs.append(self._generate_random_ioc(timestamp))

        return iocs

    def generate_iocs_for_scenario(self, events: list, base_time: datetime) -> list:
        """Generate IOCs for a specific scenario timeline."""
        iocs = []

        for event in events:
            if event["source"] != "misp":
                continue

            offset = timedelta(minutes=event.get("offset_minutes", 0))
            timestamp = (base_time + offset).strftime("%Y-%m-%dT%H:%M:%SZ")

            ioc = self._generate_random_ioc(timestamp)
            iocs.append(ioc)

        return iocs
