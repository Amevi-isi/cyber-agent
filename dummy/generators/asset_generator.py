import logging
import random
from typing import Optional
from .base_generator import BaseGenerator, logger

class AssetGenerator(BaseGenerator):
    """Generator for asset inventory (CMDB) and user data."""

    def __init__(self, config: dict = None):
        super().__init__(config)
        self.servers = []
        self.workstations = []
        self.users = []

    def generate_assets(self, server_count: int = 30, workstation_count: int = 70) -> list:
        """Generate asset inventory."""
        logger.info(f"Starting asset generation: {server_count} servers, {workstation_count} workstations")
        assets = []
        
        hostnames = self.get_dict("hostnames", ["srv-test-01", "wk-test-01"])
        first_names = self.get_dict("first_names", ["Jean", "Pierre"])
        last_names = self.get_dict("last_names", ["Dupont", "Martin"])
        departments = self.get_dict("departments", ["IT", "Finance"])
        
        services_list = ["HTTP", "HTTPS", "SSH", "RDP", "SMB", "DNS", "MySQL", "PostgreSQL"]
        software_list = ["Apache 2.4", "Nginx 1.24", "MySQL 8.0", "PostgreSQL 15", "Docker 24", "Python 3.11"]
        os_types = ["Windows Server 2022", "Ubuntu 22.04", "CentOS 8", "Windows Server 2019"]
        os_versions = ["10.0.20348", "22.04", "8", "10.0.17763"]
        
        logger.debug("Generating servers...")
        
        for i in range(server_count):
            hostname = f"srv-{random.choice(['web', 'app', 'db', 'file', 'mail', 'backup'])}-{random.randint(1, 10):02d}"
            assets.append({
                "asset_id": f"ASSET-SRV-{i+1:03d}",
                "hostname": hostname,
                "ip_address": f"192.168.10.{random.randint(10, 50)}",
                "mac_address": self.generate_mac(),
                "os_type": random.choice(os_types),
                "os_version": random.choice(os_versions),
                "asset_type": "server",
                "criticality": random.choice(["critical", "high", "medium"]),
                "department": random.choice(departments),
                "owner": f"{random.choice(first_names).lower()}.{random.choice(last_names).lower()}@corp.local",
                "location": random.choice(["Paris-DC", "Lyon-Office", "Brest-DC"]),
                "vlan": f"VLAN-{random.randint(10, 50)}",
                "services": random.choices(services_list, k=random.randint(2, 5)),
                "installed_software": random.choices(software_list, k=random.randint(2, 4)),
                "patch_level": random.choice(["2024-01", "2024-02", "critical-missing"]),
                "edr_agent": random.choice(["CrowdStrike", "SentinelOne", "Microsoft Defender"]),
                "last_seen": self.random_timestamp()
            })
        
        logger.debug("Generating workstations...")
        
        workstation_software = ["Office 365", "Chrome", "Firefox", "VS Code", "Python 3.11"]
        
        for i in range(workstation_count):
            hostname = f"wk-{random.choice(['station', 'laptop'])}-{random.choice(departments).lower()}-{random.randint(1, 30):02d}"
            assets.append({
                "asset_id": f"ASSET-WK-{i+1:03d}",
                "hostname": hostname,
                "ip_address": f"192.168.1.{random.randint(10, 200)}",
                "mac_address": self.generate_mac(),
                "os_type": random.choice(["Windows 11", "Windows 10", "Ubuntu 22.04", "macOS 13"]),
                "os_version": random.choice(["23H2", "22H2", "22.04", "13.0"]),
                "asset_type": "workstation",
                "criticality": random.choice(["high", "medium", "low"]),
                "department": random.choice(departments),
                "owner": f"{random.choice(first_names).lower()}.{random.choice(last_names).lower()}@corp.local",
                "location": random.choice(["Paris-DC", "Lyon-Office", "Brest-DC", "Remote"]),
                "vlan": f"VLAN-{random.randint(100, 200)}",
                "services": ["RDP", "SMB"],
                "installed_software": random.choices(workstation_software, k=min(4, len(workstation_software))),
                "patch_level": random.choice(["2024-01", "2024-02", "critical-missing"]),
                "edr_agent": random.choice(["CrowdStrike", "SentinelOne", "Microsoft Defender"]),
                "last_seen": self.random_timestamp()
            })
        
        logger.debug("Assigning servers/workstations...")
        
        self.servers = [a for a in assets if a["asset_type"] == "server"]
        self.workstations = [a for a in assets if a["asset_type"] == "workstation"]
        
        logger.info(f"Generated {len(assets)} assets")
        return assets

    def generate_users(self, total_count: int = 150, privileged_ratio: float = 0.1) -> list:
        """Generate user directory."""
        logger.info(f"Starting user generation: {total_count} users")
        users = []
        
        first_names = self.get_dict("first_names") or ["Jean", "Pierre"]
        last_names = self.get_dict("last_names") or ["Dupont", "Martin"]
        departments = self.get_dict("departments") or ["IT", "Finance"]
        job_titles = self.get_dict("job_titles") or ["Analyst", "Developer"]
        groups = self.get_dict("groups") or ["Domain Users", "IT-Security"]
        privileged_groups = self.get_dict("privileged_groups") or ["Domain Admins"]
        
        logger.debug(f"first_names: {first_names}")
        logger.debug(f"last_names: {last_names}")
        
        privileged_count = int(total_count * privileged_ratio)
        
        for i in range(total_count):
            first = random.choice(first_names)
            last = random.choice(last_names)
            username = f"{first.lower()}.{last.lower()}"
            
            user = {
                "user_id": f"USR-{i+1:04d}",
                "username": username,
                "email": f"{username}@corp.local",
                "full_name": f"{first} {last}",
                "department": random.choice(departments),
                "job_title": random.choice(job_titles),
                "manager": f"{random.choice(first_names).lower()}.{random.choice(last_names).lower()}@corp.local" if random.random() > 0.1 else None,
                "groups": [random.choice(groups)],
                "privileged": i < privileged_count,
                "mfa_enabled": random.choice([True, False, True, True]),
                "last_login": "2026-03-05T12:00:00Z",
                "login_history": [
                    {"ip": f"192.168.1.{random.randint(10,200)}", "date": "2026-03-05T10:00:00Z"} 
                    for _ in range(random.randint(1, 5))
                ],
                "risk_score": random.randint(0, 30) if i >= privileged_count else random.randint(20, 60)
            }
            
            if user["privileged"]:
                user["groups"].append(random.choice(privileged_groups))
                user["risk_score"] = min(user["risk_score"] + 20, 100)
            
            users.append(user)
        
        self.users = users
        logger.info(f"Generated {len(users)} users")
        return users

    def get_asset_by_hostname(self, hostname: str) -> Optional[dict]:
        """Get asset by hostname."""
        for asset in self.servers + self.workstations:
            if asset["hostname"] == hostname:
                return asset
        return None

    def get_asset_by_ip(self, ip: str) -> Optional[dict]:
        """Get asset by IP."""
        for asset in self.servers + self.workstations:
            if asset["ip_address"] == ip:
                return asset
        return None

    def get_user_by_username(self, username: str) -> Optional[dict]:
        """Get user by username."""
        for user in self.users:
            if user["username"] == username:
                return user
        return None

    def get_random_asset(self, asset_type: str = "server") -> Optional[dict]:
        """Get random asset of specified type."""
        if asset_type == "server":
            return random.choice(self.servers) if self.servers else None
        elif asset_type == "workstation":
            return random.choice(self.workstations) if self.workstations else None
        return None

    def get_random_user(self, privileged: bool = False) -> Optional[dict]:
        """Get random user, optionally privileged."""
        users = [u for u in self.users if u["privileged"] == privileged] if privileged else self.users
        return random.choice(users) if users else None
