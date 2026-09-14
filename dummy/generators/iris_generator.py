import random
import string
from datetime import datetime, timedelta
from .base_generator import BaseGenerator


class IRISGenerator(BaseGenerator):
    """Generator for DFIR-IRIS investigation cases."""

    def __init__(self, config: dict = None):
        super().__init__(config)
        self.case_names = [
            "Incident Ransomware {month} 2024",
            "Suspicious Login Investigation",
            "Data Breach Response",
            "Malware Analysis Request",
            "Phishing Campaign Investigation",
            "Insider Threat Investigation",
            "APT Activity Detection",
            "Unauthorized Access Alert"
        ]

    def _generate_hash(self, length: int = 64) -> str:
        """Generate random hash."""
        return ''.join(random.choices(string.hexdigits.lower(), k=length))

    def generate_case(self, timestamp: str = None, case_type: str = None) -> dict:
        """Generate a single IRIS case."""
        if timestamp is None:
            timestamp = self.random_timestamp()

        if case_type == "ransomware":
            return self._generate_ransomware_case(timestamp)
        elif case_type == "phishing":
            return self._generate_phishing_case(timestamp)
        elif case_type == "breach":
            return self._generate_breach_case(timestamp)
        
        return self._generate_random_case(timestamp)

    def _generate_ransomware_case(self, timestamp: str) -> dict:
        """Generate ransomware case."""
        return {
            "case_id": random.randint(1, 1000),
            "case_uuid": self.uuid4(),
            "case_name": "Incident Ransomware LockBit January 2024",
            "case_description": "Infection par ransomware LockBit sur le serveur FILESRV01. Chiffrement de fichiers detecte a 14:30 UTC.",
            "case_open_date": timestamp,
            "case_close_date": None,
            "case_status_id": 1,
            "case_severity_id": 4,
            "case_owner_id": random.randint(1, 10),
            "case_customer_id": 1,
            "case_classification_id": 1,
            "ioc": [
                {
                    "ioc_id": random.randint(1, 1000),
                    "ioc_value": "lockbit.exe",
                    "ioc_type_id": 3,
                    "ioc_description": "Fichier ransomware detecte",
                    "ioc_tags": "ransomware,lockbit,executable"
                },
                {
                    "ioc_id": random.randint(1, 1000),
                    "ioc_value": "185.220.101.42",
                    "ioc_type_id": 1,
                    "ioc_description": "C2 IP",
                    "ioc_tags": "c2,lockbit,ip"
                }
            ],
            "evidence": [
                {
                    "evidence_id": random.randint(1, 1000),
                    "evidence_uuid": self.uuid4(),
                    "evidence_type": "disk",
                    "evidence_filename": "memory-dump-srv01.raw",
                    "evidence_hash": self._generate_hash(),
                    "evidence_size": 8589934592,
                    "evidence_description": "Dump memoire du serveur infecte"
                }
            ],
            "tasks": [
                {
                    "task_id": random.randint(1, 1000),
                    "task_title": "Analyser le dump memoire",
                    "task_status": "in_progress",
                    "task_assignee_id": random.randint(1, 10)
                }
            ],
            "notes": [
                {
                    "note_id": random.randint(1, 1000),
                    "note_title": "Analyse preliminaire",
                    "note_content": "Presence de processus chiffrant les fichiers detectee. Extension .lockbit ajoutee."
                }
            ]
        }

    def _generate_phishing_case(self, timestamp: str) -> dict:
        """Generate phishing case."""
        return {
            "case_id": random.randint(1, 1000),
            "case_uuid": self.uuid4(),
            "case_name": "Phishing Campaign BEC January 2024",
            "case_description": "Campagne de phishing ciblant les employes du departement Finance. Tentative de transfert bancaire frauduleux.",
            "case_open_date": timestamp,
            "case_close_date": None,
            "case_status_id": 2,
            "case_severity_id": 3,
            "case_owner_id": random.randint(1, 10),
            "case_customer_id": 1,
            "case_classification_id": 2,
            "ioc": [
                {
                    "ioc_id": random.randint(1, 1000),
                    "ioc_value": "company-invoice.com",
                    "ioc_type_id": 2,
                    "ioc_description": "Domaine de phishing",
                    "ioc_tags": "phishing,bec,domain"
                },
                {
                    "ioc_id": random.randint(1, 1000),
                    "ioc_value": self._generate_hash(32),
                    "ioc_type_id": 3,
                    "ioc_description": "Hash du malware",
                    "ioc_tags": "phishing,malware,hash"
                }
            ],
            "evidence": [],
            "tasks": [],
            "notes": []
        }

    def _generate_breach_case(self, timestamp: str) -> dict:
        """Generate data breach case."""
        return {
            "case_id": random.randint(1, 1000),
            "case_uuid": self.uuid4(),
            "case_name": "Data Breach Notification",
            "case_description": "Fuite de donnees client suspectee. Investigation en cours pour determiner l'etendue.",
            "case_open_date": timestamp,
            "case_close_date": None,
            "case_status_id": 1,
            "case_severity_id": 4,
            "case_owner_id": random.randint(1, 10),
            "case_customer_id": 1,
            "case_classification_id": 3,
            "ioc": [],
            "evidence": [],
            "tasks": [],
            "notes": []
        }

    def _generate_random_case(self, timestamp: str) -> dict:
        """Generate random case."""
        case_name = random.choice(self.case_names).format(
            month=random.choice(["January", "February", "March", "April"])
        )
        
        return {
            "case_id": random.randint(1, 1000),
            "case_uuid": self.uuid4(),
            "case_name": case_name,
            "case_description": random.choice([
                "Investigation en cours suite a une alerte de securite.",
                "Analyse de comportement suspect detecte sur le reseau.",
                "Revue des logs suite a un incident de securite.",
                "Examen des acces non autorises."
            ]),
            "case_open_date": timestamp,
            "case_close_date": None if random.random() > 0.5 else (datetime.fromisoformat(timestamp.replace('Z', '+00:00')) + timedelta(days=random.randint(1, 30))).isoformat() + "Z",
            "case_status_id": random.randint(1, 3),
            "case_severity_id": random.randint(1, 4),
            "case_owner_id": random.randint(1, 10),
            "case_customer_id": 1,
            "case_classification_id": random.randint(1, 5),
            "ioc": [],
            "evidence": [],
            "tasks": [],
            "notes": []
        }

    def generate_cases(self, count: int = 50, start: datetime = None, end: datetime = None) -> list:
        """Generate multiple cases."""
        if start is None:
            start = datetime.utcnow() - timedelta(days=90)
        if end is None:
            end = datetime.utcnow()

        cases = []
        for _ in range(count):
            timestamp = self.random_timestamp(start, end)
            cases.append(self._generate_random_case(timestamp))

        return cases

    def generate_cases_for_scenario(self, events: list, base_time: datetime) -> list:
        """Generate cases for a specific scenario timeline."""
        cases = []

        for event in events:
            if event["source"] != "iris":
                continue

            offset = timedelta(minutes=event.get("offset_minutes", 0))
            timestamp = (base_time + offset).strftime("%Y-%m-%dT%H:%M:%SZ")

            if event["event"] == "case_opened":
                cases.append(self._generate_ransomware_case(timestamp))

        return cases
