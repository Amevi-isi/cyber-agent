import random
from datetime import datetime, timedelta
from .base_generator import BaseGenerator


class ADGenerator(BaseGenerator):
    """Generator for Active Directory / Windows Events."""

    def __init__(self, config: dict = None):
        super().__init__(config)
        self.domain = "corp.local"
        self.dcs = ["DC01", "DC02", "DC03"]

    def generate_event(self, timestamp: str = None, event_type: str = None) -> dict:
        """Generate a single AD event."""
        if timestamp is None:
            timestamp = self.random_timestamp()

        if event_type == "user_created":
            return self._generate_user_created(timestamp)
        elif event_type == "privilege_escalation":
            return self._generate_privilege_escalation(timestamp)
        elif event_type == "anormal_login":
            return self._generate_anormal_login(timestamp)
        elif event_type == "kerberoasting":
            return self._generate_kerberoasting(timestamp)
        elif event_type == "after_hours_login":
            return self._generate_after_hours_login(timestamp)
        
        return self._generate_random_event(timestamp)

    def _generate_user_created(self, timestamp: str) -> dict:
        """Generate user creation event."""
        return {
            "EventID": 4720,
            "TimeCreated": timestamp,
            "Computer": random.choice(self.dcs) + "." + self.domain,
            "SubjectUserSid": "S-1-5-18",
            "SubjectUserName": "administrator",
            "SubjectDomainName": self.domain.upper(),
            "TargetUserSid": f"S-1-5-21-{random.randint(100000,999999)}-{random.randint(100000,999999)}-{random.randint(100000,999999)}-{random.randint(1000,9999)}",
            "TargetUserName": "svc_backup",
            "TargetDomainName": self.domain.upper(),
            "LogonType": None,
            "IpAddress": None,
            "IpPort": None,
            "AuthenticationPackageName": "Kerberos",
            "LmPackageName": None,
            "KeyLength": 0,
            "ProcessName": None,
            "CommandLine": "net user svc_backup P@ssw0rd123 /add /domain",
            "ObjectClass": "user",
            "ObjectDN": f"CN=svc_backup,OU=Users,{self._get_domain_dn()}",
            "GroupName": None,
            "MemberName": None
        }

    def _generate_privilege_escalation(self, timestamp: str) -> dict:
        """Generate privilege escalation event."""
        return {
            "EventID": 4732,
            "TimeCreated": timestamp,
            "Computer": random.choice(self.dcs) + "." + self.domain,
            "SubjectUserSid": "S-1-5-18",
            "SubjectUserName": "administrator",
            "SubjectDomainName": self.domain.upper(),
            "TargetUserSid": f"S-1-5-21-{random.randint(100000,999999)}-{random.randint(100000,999999)}-{random.randint(100000,999999)}-{random.randint(1000,9999)}",
            "TargetUserName": "svc_backup",
            "TargetDomainName": self.domain.upper(),
            "LogonType": None,
            "IpAddress": None,
            "IpPort": None,
            "AuthenticationPackageName": "Kerberos",
            "LmPackageName": None,
            "KeyLength": 0,
            "ProcessName": None,
            "CommandLine": None,
            "ObjectClass": "user",
            "ObjectDN": None,
            "GroupName": "Domain Admins",
            "MemberName": f"CN=svc_backup,OU=Users,{self._get_domain_dn()}"
        }

    def _generate_anormal_login(self, timestamp: str) -> dict:
        """Generate abnormal login event."""
        return {
            "EventID": 4624,
            "TimeCreated": timestamp,
            "Computer": random.choice(self.dcs) + "." + self.domain,
            "SubjectUserSid": "S-1-0-0",
            "SubjectUserName": "-",
            "SubjectDomainName": "-",
            "TargetUserSid": f"S-1-5-21-{random.randint(100000,999999)}-{random.randint(100000,999999)}-{random.randint(100000,999999)}-{random.randint(1000,9999)}",
            "TargetUserName": random.choice(["admin", "john.doe", "jane.smith"]),
            "TargetDomainName": self.domain.upper(),
            "LogonType": 10,
            "IpAddress": random.choice(["185.220.101.50", "45.142.212.100"]),
            "IpPort": random.randint(40000, 60000),
            "AuthenticationPackageName": "NTLM",
            "LmPackageName": "NTLM V2",
            "KeyLength": 128,
            "ProcessName": "C:\\Windows\\System32\\svchost.exe",
            "CommandLine": None,
            "ObjectClass": None,
            "ObjectDN": None,
            "GroupName": None,
            "MemberName": None
        }

    def _generate_kerberoasting(self, timestamp: str) -> dict:
        """Generate Kerberoasting event."""
        return {
            "EventID": 4769,
            "TimeCreated": timestamp,
            "Computer": random.choice(self.dcs) + "." + self.domain,
            "SubjectUserSid": "S-1-5-18",
            "SubjectUserName": random.choice(["john.doe", "admin", "jane.smith"]),
            "SubjectDomainName": self.domain.upper(),
            "TargetUserSid": f"S-1-5-21-{random.randint(100000,999999)}-{random.randint(100000,999999)}-{random.randint(100000,999999)}-{random.randint(1000,9999)}",
            "TargetUserName": f"svc_{random.choice(['backup', 'sql', 'web', 'app'])}",
            "TargetDomainName": self.domain.upper(),
            "LogonType": None,
            "IpAddress": f"192.168.{random.randint(1,3)}.{random.randint(1,254)}",
            "IpPort": None,
            "AuthenticationPackageName": "Kerberos",
            "LmPackageName": None,
            "KeyLength": 0,
            "ProcessName": "C:\\Windows\\System32\\lsass.exe",
            "CommandLine": None,
            "ObjectClass": None,
            "ObjectDN": None,
            "GroupName": None,
            "MemberName": None
        }

    def _generate_after_hours_login(self, timestamp: str) -> dict:
        """Generate after hours login event."""
        return {
            "EventID": 4624,
            "TimeCreated": timestamp,
            "Computer": random.choice(self.dcs) + "." + self.domain,
            "SubjectUserSid": "S-1-0-0",
            "SubjectUserName": "-",
            "SubjectDomainName": "-",
            "TargetUserSid": f"S-1-5-21-{random.randint(100000,999999)}-{random.randint(100000,999999)}-{random.randint(100000,999999)}-{random.randint(1000,9999)}",
            "TargetUserName": random.choice(["john.doe", "jane.smith"]),
            "TargetDomainName": self.domain.upper(),
            "LogonType": 10,
            "IpAddress": f"192.168.1.{random.randint(10, 200)}",
            "IpPort": None,
            "AuthenticationPackageName": "Kerberos",
            "LmPackageName": "NTLM V2",
            "KeyLength": 128,
            "ProcessName": "C:\\Windows\\System32\\svchost.exe",
            "CommandLine": None,
            "ObjectClass": None,
            "ObjectDN": None,
            "GroupName": None,
            "MemberName": None
        }

    def _generate_random_event(self, timestamp: str) -> dict:
        """Generate random AD event."""
        event_ids = [4624, 4625, 4648, 4720, 4722, 4723, 4724, 4725, 4726, 4728, 4729, 4730, 4732, 4733, 4735, 4740, 4767, 4769, 4776]
        event_id = random.choice(event_ids)
        
        return {
            "EventID": event_id,
            "TimeCreated": timestamp,
            "Computer": random.choice(self.dcs) + "." + self.domain,
            "SubjectUserSid": "S-1-5-18",
            "SubjectUserName": random.choice(["SYSTEM", "administrator"]),
            "SubjectDomainName": self.domain.upper(),
            "TargetUserSid": f"S-1-5-21-{random.randint(100000,999999)}-{random.randint(100000,999999)}-{random.randint(100000,999999)}-{random.randint(1000,9999)}",
            "TargetUserName": random.choice(["admin", "john.doe", "jane.smith", "guest"]),
            "TargetDomainName": self.domain.upper(),
            "LogonType": random.choice([2, 3, 7, 10]),
            "IpAddress": self.random_ip(),
            "IpPort": random.randint(40000, 60000),
            "AuthenticationPackageName": random.choice(["NTLM", "Kerberos"]),
            "LmPackageName": "NTLM V2",
            "KeyLength": 128,
            "ProcessName": "C:\\Windows\\System32\\svchost.exe",
            "CommandLine": None,
            "ObjectClass": None,
            "ObjectDN": None,
            "GroupName": None,
            "MemberName": None
        }

    def _get_domain_dn(self) -> str:
        """Get domain DN."""
        return f"DC={self.domain.replace('.', ',DC=')}"

    def generate_events(self, count: int = 2000, start: datetime = None, end: datetime = None) -> list:
        """Generate multiple AD events."""
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
        ad_events = []

        for event in events:
            if event["source"] != "ad":
                continue

            offset = timedelta(minutes=event.get("offset_minutes", 0))
            timestamp = (base_time + offset).strftime("%Y-%m-%dT%H:%M:%SZ")

            ev = self.generate_event(timestamp=timestamp, event_type=event["event"])
            ad_events.append(ev)

        return ad_events
