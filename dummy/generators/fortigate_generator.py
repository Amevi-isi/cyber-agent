import random
from datetime import datetime, timedelta
from .base_generator import BaseGenerator


class FortiGateGenerator(BaseGenerator):
    """Generator for FortiGate firewall logs."""

    def __init__(self, config: dict = None):
        super().__init__(config)
        self.devices = [
            {"name": "FGT-PRD-01", "id": "FGVMEV0000000001"},
            {"name": "FGT-PRD-02", "id": "FGVMEV0000000002"},
            {"name": "FGT-DEV-01", "id": "FGVMEV0000000003"}
        ]
        self.interfaces = ["port1", "port2", "port3", "port4", "wan1", "wan2"]
        self.services = ["HTTPS", "HTTP", "DNS", "SSH", "SMB", "RDP", "SMTP", "POP3", "IMAP"]

    def generate_log(self, timestamp: datetime = None, event_type: str = None) -> dict:
        """Generate a single FortiGate log entry."""
        if timestamp is None:
            timestamp = datetime.utcnow() - timedelta(minutes=random.randint(0, 1440))

        if event_type == "email_received":
            return self._generate_email_received(timestamp)
        elif event_type == "email_exfiltration":
            return self._generate_email_exfiltration(timestamp)
        elif event_type == "cloud_upload":
            return self._generate_cloud_upload(timestamp)
        elif event_type == "c2_blocked":
            return self._generate_c2_blocked(timestamp)
        
        return self._generate_random_log(timestamp)

    def _generate_email_received(self, timestamp: datetime) -> dict:
        """Generate email received log."""
        return {
            "date": timestamp.strftime("%Y-%m-%d"),
            "time": timestamp.strftime("%H:%M:%S"),
            "devname": random.choice(self.devices)["name"],
            "devid": random.choice(self.devices)["id"],
            "logid": "0000000013",
            "type": "utm",
            "subtype": "emailfilter",
            "level": "warning",
            "vd": "root",
            "srcip": random.choice(["185.220.101.50", "45.142.212.100"]),
            "srcport": random.randint(40000, 60000),
            "srcintf": random.choice(self.interfaces),
            "dstip": f"192.168.10.{random.randint(10, 50)}",
            "dstport": 25,
            "dstintf": random.choice(self.interfaces),
            "sessionid": random.randint(1000000, 9999999),
            "proto": 6,
            "action": "pass",
            "policyid": random.randint(1, 50),
            "policytype": "policy",
            "service": "SMTP",
            "hostname": random.choice(["company-invoice.com", "payment-secure.net", "invoice-urgent.io"]),
            "url": f"/mail/{random.randint(1000, 9999)}",
            "webfilter": "Spam",
            "user": "",
            "group": "",
            "sentbyte": random.randint(1000, 50000),
            "rcvdbyte": random.randint(1000, 100000),
            "duration": random.randint(1, 30)
        }

    def _generate_email_exfiltration(self, timestamp: datetime) -> dict:
        """Generate email exfiltration log."""
        return {
            "date": timestamp.strftime("%Y-%m-%d"),
            "time": timestamp.strftime("%H:%M:%S"),
            "devname": random.choice(self.devices)["name"],
            "devid": random.choice(self.devices)["id"],
            "logid": "0000000020",
            "type": "traffic",
            "subtype": "forward",
            "level": "notice",
            "vd": "root",
            "srcip": f"192.168.10.{random.randint(10, 50)}",
            "srcport": random.randint(49152, 65535),
            "srcintf": random.choice(self.interfaces),
            "dstip": random.choice(["185.220.101.50", "45.142.212.100"]),
            "dstport": 587,
            "dstintf": random.choice(self.interfaces),
            "sessionid": random.randint(1000000, 9999999),
            "proto": 6,
            "action": "accept",
            "policyid": random.randint(1, 50),
            "policytype": "policy",
            "service": "SMTP",
            "user": f"{random.choice(['john.doe', 'admin', 'jane.smith'])}@corp.local",
            "group": random.choice(["VPN-Users", "Remote-Workers"]),
            "sentbyte": random.randint(5000000, 20000000),
            "rcvdbyte": random.randint(1000, 10000),
            "duration": random.randint(60, 600)
        }

    def _generate_cloud_upload(self, timestamp: datetime) -> dict:
        """Generate cloud upload log."""
        return {
            "date": timestamp.strftime("%Y-%m-%d"),
            "time": timestamp.strftime("%H:%M:%S"),
            "devname": random.choice(self.devices)["name"],
            "devid": random.choice(self.devices)["id"],
            "logid": "0000000020",
            "type": "traffic",
            "subtype": "forward",
            "level": "notice",
            "vd": "root",
            "srcip": f"192.168.1.{random.randint(10, 200)}",
            "srcport": random.randint(49152, 65535),
            "srcintf": random.choice(self.interfaces),
            "dstip": random.choice(["172.217.14.206", "13.107.42.14", "52.94.76.10"]),
            "dstport": 443,
            "dstintf": random.choice(self.interfaces),
            "sessionid": random.randint(1000000, 9999999),
            "proto": 6,
            "action": "accept",
            "policyid": random.randint(1, 50),
            "policytype": "policy",
            "service": "HTTPS",
            "hostname": random.choice(["dropbox.com", "drive.google.com", "onedrive.live.com", "icloud.com"]),
            "url": "/upload",
            "appcat": "Cloud Storage",
            "app": random.choice(["Dropbox", "Google Drive", "OneDrive", "iCloud"]),
            "user": f"{random.choice(['john.doe', 'admin', 'jane.smith'])}@corp.local",
            "group": random.choice(["VPN-Users", "Remote-Workers"]),
            "sentbyte": random.randint(100000000, 5000000000),
            "rcvdbyte": random.randint(10000, 1000000),
            "duration": random.randint(300, 3600)
        }

    def _generate_c2_blocked(self, timestamp: datetime) -> dict:
        """Generate C2 blocked log."""
        return {
            "date": timestamp.strftime("%Y-%m-%d"),
            "time": timestamp.strftime("%H:%M:%S"),
            "devname": random.choice(self.devices)["name"],
            "devid": random.choice(self.devices)["id"],
            "logid": "0000000020",
            "type": "traffic",
            "subtype": "forward",
            "level": "warning",
            "vd": "root",
            "srcip": f"192.168.10.{random.randint(10, 50)}",
            "srcport": random.randint(49152, 65535),
            "srcintf": random.choice(self.interfaces),
            "dstip": random.choice(["185.220.101.42", "185.220.101.50"]),
            "dstport": 443,
            "dstintf": random.choice(self.interfaces),
            "sessionid": random.randint(1000000, 9999999),
            "proto": 6,
            "action": "deny",
            "policyid": random.randint(1, 50),
            "policytype": "policy",
            "service": "HTTPS",
            "user": random.choice(["SYSTEM", "admin"]),
            "group": "",
            "sentbyte": 0,
            "rcvdbyte": 0,
            "duration": 0
        }

    def _generate_random_log(self, timestamp: datetime) -> dict:
        """Generate random FortiGate log."""
        return {
            "date": timestamp.strftime("%Y-%m-%d"),
            "time": timestamp.strftime("%H:%M:%S"),
            "devname": random.choice(self.devices)["name"],
            "devid": random.choice(self.devices)["id"],
            "logid": random.choice(["0000000020", "0000000013", "0000000015"]),
            "type": random.choice(["traffic", "utm", "event"]),
            "subtype": random.choice(["forward", "local", "sslvpn", "emailfilter"]),
            "level": random.choice(["notice", "warning", "critical"]),
            "vd": "root",
            "srcip": self.random_ip(),
            "srcport": self.random_port(),
            "srcintf": random.choice(self.interfaces),
            "dstip": self.random_ip(),
            "dstport": self.random_port(),
            "dstintf": random.choice(self.interfaces),
            "sessionid": random.randint(1000000, 9999999),
            "proto": random.choice([6, 17]),
            "action": random.choice(["accept", "deny"]),
            "policyid": random.randint(1, 50),
            "policytype": "policy",
            "service": random.choice(self.services),
            "user": f"{random.choice(['john.doe', 'admin', 'jane.smith'])}@corp.local" if random.random() > 0.3 else "",
            "group": random.choice(["VPN-Users", "Remote-Workers"]) if random.random() > 0.5 else "",
            "sentbyte": random.randint(100, 10000000),
            "rcvdbyte": random.randint(100, 10000000),
            "duration": random.randint(1, 3600)
        }

    def generate_logs(self, count: int = 3000, start: datetime = None, end: datetime = None) -> list:
        """Generate multiple FortiGate logs."""
        if start is None:
            start = datetime.utcnow() - timedelta(days=1)
        if end is None:
            end = datetime.utcnow()

        logs = []
        for _ in range(count):
            delta = end - start
            random_seconds = random.randint(0, int(delta.total_seconds()))
            timestamp = start + timedelta(seconds=random_seconds)
            logs.append(self._generate_random_log(timestamp))

        return logs

    def generate_logs_for_scenario(self, events: list, base_time: datetime) -> list:
        """Generate logs for a specific scenario timeline."""
        logs = []

        for event in events:
            if event["source"] != "fortigate":
                continue

            offset = timedelta(minutes=event.get("offset_minutes", 0))
            timestamp = base_time + offset

            log = self.generate_log(timestamp=timestamp, event_type=event["event"])
            logs.append(log)

        return logs
