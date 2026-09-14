import random
import string
from datetime import datetime, timedelta
from .base_generator import BaseGenerator


class UKWELIGenerator(BaseGenerator):
    """Generator for UKWELI (URL/File analysis sandbox) submissions."""

    def __init__(self, config: dict = None):
        super().__init__(config)

    def _generate_hash(self, length: int = 32) -> str:
        """Generate random hash."""
        return ''.join(random.choices(string.hexdigits.lower(), k=length))

    def generate_submission(self, timestamp: str = None, submission_type: str = None) -> dict:
        """Generate a single UKWELI submission."""
        if timestamp is None:
            timestamp = self.random_timestamp()

        return self._generate_random_submission(timestamp)

    def _generate_random_submission(self, timestamp: str) -> dict:
        """Generate random submission."""
        verdict = random.choices(
            ["malicious", "suspicious", "clean"],
            weights=[0.3, 0.3, 0.4]
        )[0]
        
        malware = random.choice(["TrickBot", "Emotet", "LockBit", "QakBot", None]) if verdict != "clean" else None
        file_type = random.choice(["application/x-dosexec", "application/x-msdownload", "application/pdf", "application/vnd.ms-excel"])
        
        return {
            "submission_id": f"sub_{random.randint(100000000, 999999999)}",
            "submission_date": timestamp,
            "submitter": random.choice(["wazuh-agent", "manual-upload", "fortigate", "edr-agent"]),
            "url": f"http://{random.choice(['evil-c2.com', 'malware-server.net', 'suspicious-domain.xyz'])}/downloads/{random.choice(['invoice.pdf.exe', 'update.exe', 'document.docm'])}" if random.random() > 0.3 else None,
            "file_name": random.choice(["invoice.pdf.exe", "update.exe", "document.docm", "script.ps1", "payload.dll"]),
            "file_type": file_type,
            "file_size": random.randint(10000, 1000000),
            "sha256": self._generate_hash(64),
            "md5": self._generate_hash(32),
            "analysis_status": "completed",
            "analysis_date": timestamp,
            "detection_score": random.randint(0, 100) if verdict != "clean" else random.randint(0, 20),
            "verdict": verdict,
            "malware_family": malware,
            "malware_type": random.choice(["trojan", "ransomware", "spyware", "dropper"]) if verdict != "clean" else None,
            "behavior_summary": self._generate_behaviors(verdict),
            "network_indicators": self._generate_network_indicators(verdict),
            "file_indicators": self._generate_file_indicators(verdict),
            "registry_indicators": self._generate_registry_indicators(verdict),
            "screenshots": [f"https://sandbox.example.com/{random.randint(10000, 99999)}/screen{i}.png" for i in range(1, 4)] if verdict != "clean" else [],
            "report_url": f"https://sandbox.example.com/report/{random.randint(10000, 99999)}"
        }

    def _generate_behaviors(self, verdict: str) -> list:
        """Generate behavior summary."""
        if verdict == "clean":
            return []
        
        behaviors = [
            "file-encryption",
            "registry-modification",
            "network-communication",
            "process-injection",
            "credential-access",
            "persistence",
            "defense-evasion",
            "discovery",
            "lateral-movement",
            "data-exfiltration"
        ]
        
        return random.sample(behaviors, k=random.randint(2, 5))

    def _generate_network_indicators(self, verdict: str) -> list:
        """Generate network indicators."""
        if verdict == "clean":
            return []
        
        return [
            {
                "ip": random.choice(["185.220.101.42", "45.142.212.100", "91.121.87.10"]),
                "port": random.choice([443, 8080, 4444, 80]),
                "protocol": random.choice(["https", "http", "tcp"]),
                "direction": random.choice(["outbound", "inbound"])
            }
        ]

    def _generate_file_indicators(self, verdict: str) -> list:
        """Generate file indicators."""
        if verdict == "clean":
            return []
        
        return [
            {
                "path": random.choice([
                    "C:\\Windows\\Temp\\evil.dll",
                    "C:\\Users\\Public\\Downloads\\payload.exe",
                    "C:\\ProgramData\\Microsoft\\Windows\\startup\\persist.bat"
                ]),
                "operation": random.choice(["created", "modified", "executed"])
            }
        ]

    def _generate_registry_indicators(self, verdict: str) -> list:
        """Generate registry indicators."""
        if verdict == "clean":
            return []
        
        return [
            {
                "key": random.choice([
                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "HKLM\\SYSTEM\\CurrentControlSet\\Services"
                ]),
                "value": random.choice(["evil.exe", "persist.dll", "update.bat"])
            }
        ]

    def generate_submissions(self, count: int = 100, start: datetime = None, end: datetime = None) -> list:
        """Generate multiple submissions."""
        if start is None:
            start = datetime.utcnow() - timedelta(days=30)
        if end is None:
            end = datetime.utcnow()

        submissions = []
        for _ in range(count):
            timestamp = self.random_timestamp(start, end)
            submissions.append(self._generate_random_submission(timestamp))

        return submissions
