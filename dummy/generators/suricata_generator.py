import random
from datetime import datetime, timedelta
from .base_generator import BaseGenerator


class SuricataGenerator(BaseGenerator):
    """Generator for Suricata IDS/IPS events."""

    def __init__(self, config: dict = None):
        super().__init__(config)
        self.signatures = []
        self._load_signatures()

    def _load_signatures(self):
        """Load Suricata signatures from dictionary."""
        self.signatures = self.get_dict("signatures", [])

    def generate_event(self, timestamp: str = None, event_type: str = None) -> dict:
        """Generate a single Suricata event."""
        if timestamp is None:
            timestamp = self.random_timestamp()

        if event_type == "c2_beaconing":
            return self._generate_c2_beaconing(timestamp)
        elif event_type == "dns_query_suspicious":
            return self._generate_dns_query_suspicious(timestamp)
        elif event_type == "data_exfiltration":
            return self._generate_data_exfiltration(timestamp)
        elif event_type == "exfiltration":
            return self._generate_exfiltration(timestamp)
        elif event_type == "initial_access":
            return self._generate_initial_access(timestamp)
        elif event_type == "malware_download":
            return self._generate_malware_download(timestamp)
        
        return self._generate_random_event(timestamp)

    def _generate_c2_beaconing(self, timestamp: str) -> dict:
        """Generate C2 beaconing event."""
        return {
            "timestamp": timestamp,
            "event_type": "alert",
            "src_ip": f"192.168.10.{random.randint(10, 50)}",
            "src_port": random.randint(49152, 65535),
            "dest_ip": random.choice(["185.220.101.42", "185.220.101.50", "45.142.212.100"]),
            "dest_port": 443,
            "proto": "TCP",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 2028001,
                "rev": 2,
                "signature": "ET BEACON C2 Encrypted Traffic",
                "category": "Malware Command and Control Activity",
                "severity": 1
            },
            "tls": {
                "sni": random.choice(["evil-c2.com", "malware-c2.net", "c2-infrastructure.io"])
            },
            "flow_id": self.uuid4()
        }

    def _generate_dns_query_suspicious(self, timestamp: str) -> dict:
        """Generate suspicious DNS query event."""
        return {
            "timestamp": timestamp,
            "event_type": "alert",
            "src_ip": f"192.168.10.{random.randint(10, 50)}",
            "src_port": random.randint(49152, 65535),
            "dest_ip": f"192.168.{random.randint(1,3)}.{random.randint(1,254)}",
            "dest_port": 53,
            "proto": "UDP",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 2022001,
                "rev": 2,
                "signature": "ET DNS Tunnel Query",
                "category": "Potentially Bad Traffic",
                "severity": 2
            },
            "dns": {
                "rrname": random.choice(["suspicious-domain.xyz", "long-subdomain.evil-c2.com", "data-exfil.malware.net"])
            },
            "flow_id": self.uuid4()
        }

    def _generate_data_exfiltration(self, timestamp: str) -> dict:
        """Generate data exfiltration event."""
        return {
            "timestamp": timestamp,
            "event_type": "alert",
            "src_ip": f"192.168.10.{random.randint(10, 50)}",
            "src_port": random.randint(49152, 65535),
            "dest_ip": random.choice(["185.220.101.42", "185.220.101.50"]),
            "dest_port": random.choice([8080, 443, 21]),
            "proto": "TCP",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 2014501,
                "rev": 3,
                "signature": "ET DATA Exfiltration Large Data Chunk",
                "category": "Attempted Information Leak",
                "severity": 2
            },
            "http": {
                "hostname": random.choice(["evil-c2.com", "data-staging.net"]),
                "url": "/upload",
                "http_method": "POST"
            },
            "flow_id": self.uuid4()
        }

    def _generate_exfiltration(self, timestamp: str) -> dict:
        """Generate general exfiltration event."""
        return {
            "timestamp": timestamp,
            "event_type": "alert",
            "src_ip": f"192.168.10.{random.randint(10, 50)}",
            "src_port": random.randint(49152, 65535),
            "dest_ip": random.choice(["185.220.101.42", "23.129.64.130"]),
            "dest_port": 443,
            "proto": "TCP",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 2014501,
                "rev": 3,
                "signature": "ET DATA Exfiltration Large Data Chunk",
                "category": "Attempted Information Leak",
                "severity": 2
            },
            "flow_id": self.uuid4()
        }

    def _generate_initial_access(self, timestamp: str) -> dict:
        """Generate initial access attempt event."""
        return {
            "timestamp": timestamp,
            "event_type": "alert",
            "src_ip": random.choice(["45.142.212.100", "185.220.101.42"]),
            "src_port": random.randint(40000, 60000),
            "dest_ip": f"192.168.10.{random.randint(10, 50)}",
            "dest_port": random.choice([22, 80, 443, 3389]),
            "proto": "TCP",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 2010002,
                "rev": 3,
                "signature": "ET SCAN Potential SSH Bruteforce",
                "category": "Attempted Information Leak",
                "severity": 2
            },
            "flow_id": self.uuid4()
        }

    def _generate_malware_download(self, timestamp: str) -> dict:
        """Generate malware download event."""
        return {
            "timestamp": timestamp,
            "event_type": "alert",
            "src_ip": f"192.168.10.{random.randint(10, 50)}",
            "src_port": random.randint(49152, 65535),
            "dest_ip": random.choice(["185.220.101.42", "91.121.87.10"]),
            "dest_port": 80,
            "proto": "TCP",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 2021001,
                "rev": 3,
                "signature": "ET TROJAN JS/Nemucod Downloader",
                "category": "Network Trojan Activity",
                "severity": 1
            },
            "http": {
                "hostname": random.choice(["evil-c2.com", "malware-server.net"]),
                "url": f"/downloads/{random.choice(['invoice.exe', 'update.exe', 'document.pdf.exe'])}",
                "http_method": "GET",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            },
            "fileinfo": {
                "filename": random.choice(["invoice.exe", "update.exe", "document.pdf.exe"]),
                "size": random.randint(50000, 500000),
                "md5": self._generate_hash(32),
                "sha256": self._generate_hash(64)
            },
            "flow_id": self.uuid4()
        }

    def _generate_random_event(self, timestamp: str) -> dict:
        """Generate random Suricata event."""
        if not self.signatures:
            sig = {"id": 2010001, "rev": 1, "category": "Scan", "severity": 2, "signature": "ET SCAN Potential Scan"}
        else:
            sig = random.choice(self.signatures)

        return {
            "timestamp": timestamp,
            "event_type": random.choice(["alert", "http", "dns", "tls", "flow"]),
            "src_ip": self.random_ip(),
            "src_port": self.random_port(),
            "dest_ip": self.random_ip(),
            "dest_port": self.random_port(),
            "proto": random.choice(["TCP", "UDP"]),
            "alert": {
                "action": random.choice(["allowed", "blocked"]),
                "gid": 1,
                "signature_id": sig["id"],
                "rev": sig["rev"],
                "signature": sig["signature"],
                "category": sig["category"],
                "severity": sig["severity"]
            },
            "flow_id": self.uuid4()
        }

    def _generate_hash(self, length: int) -> str:
        """Generate random hex hash."""
        import string
        return ''.join(random.choices(string.hexdigits.lower(), k=length))

    def generate_events(self, count: int = 1000, start: datetime = None, end: datetime = None) -> list:
        """Generate multiple Suricata events."""
        if start is None:
            start = datetime.utcnow() - timedelta(days=1)
        if end is None:
            end = datetime.utcnow()

        events = []
        for _ in range(count):
            timestamp = self.random_timestamp(start, end)
            events.append(self._generate_random_event(timestamp))

        return events

    def generate_events_for_scenario(self, events: list, base_time: datetime) -> list:
        """Generate events for a specific scenario timeline."""
        suricata_events = []

        for event in events:
            if event["source"] != "suricata":
                continue

            offset = timedelta(minutes=event.get("offset_minutes", 0))
            timestamp = (base_time + offset).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

            ev = self.generate_event(timestamp=timestamp, event_type=event["event"])
            suricata_events.append(ev)

        return suricata_events
