import json
import logging
import random
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional
import ipaddress

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("dummy.generator")


class BaseGenerator:
    """Base class for all data generators."""

    def __init__(self, config: dict = None):
        self.config = config or {}
        self._dictionaries = {}
        self._load_dictionaries()

    def _load_dictionaries(self):
        """Load all dictionary files."""
        dict_dir = Path(__file__).parent.parent / "data" / "dictionaries"
        logger.info(f"Loading dictionaries from: {dict_dir}")
        
        if not dict_dir.exists():
            logger.warning(f"Dictionary directory does not exist: {dict_dir}")
            return
        
        loaded = 0
        for dict_file in dict_dir.glob("*.json"):
            try:
                with open(dict_file, 'r', encoding='utf-8') as f:
                    self._dictionaries[dict_file.stem] = json.load(f)
                    loaded += 1
                    logger.debug(f"Loaded dictionary: {dict_file.stem}")
            except Exception as e:
                logger.error(f"Failed to load {dict_file}: {e}")
        
        logger.info(f"Loaded {loaded} dictionaries")

    def get_dict(self, key: str, default: Any = None) -> Any:
        """Get a value from dictionaries."""
        for dict_data in self._dictionaries.values():
            if key in dict_data:
                return dict_data[key]
        return default

    def random_ip(self, private: bool = True) -> str:
        """Generate a random IP address."""
        if private:
            return f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"
        else:
            return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

    def random_external_ip(self) -> str:
        """Generate a random external IP (simulating malicious)."""
        malicious_ips = [
            "45.142.212.100", "185.220.101.42", "185.220.101.50",
            "91.121.87.10", "195.154.181.163", "23.129.64.130",
            "104.244.76.13", "128.31.0.34", "169.254.169.254"
        ]
        return random.choice(malicious_ips) if random.random() < 0.7 else self.random_ip(private=False)

    def random_port(self) -> int:
        """Generate a random port number."""
        common = [22, 80, 443, 445, 3389, 8080, 8443, 3306, 5432, 6379]
        if random.random() < 0.8:
            return random.choice(common)
        return random.randint(1024, 65535)

    def random_timestamp(self, start: datetime = None, end: datetime = None) -> str:
        """Generate a random ISO8601 timestamp."""
        if start is None:
            start = datetime.utcnow() - timedelta(days=1)
        if end is None:
            end = datetime.utcnow()
        
        delta = end - start
        if delta.total_seconds() <= 0:
            return start.strftime("%Y-%m-%dT%H:%M:%SZ")
        random_seconds = random.randint(0, int(delta.total_seconds()))
        return (start + timedelta(seconds=random_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")

    def random_choice(self, choices: list) -> Any:
        """Random choice from a list."""
        return random.choice(choices)

    def random_int(self, min_val: int = 0, max_val: int = 100) -> int:
        """Random integer in range."""
        return random.randint(min_val, max_val)

    def uuid4(self) -> str:
        """Generate a UUID4."""
        return str(uuid.uuid4())

    def generate_mac(self) -> str:
        """Generate a random MAC address."""
        return ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])

    def load_config(self, config_path: str) -> dict:
        """Load configuration from YAML file."""
        import yaml
        with open(config_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)

    def save_json(self, data: list, filepath: str):
        """Save data as JSON."""
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def save_jsonl(self, data: list, filepath: str):
        """Save data as JSON Lines."""
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            for item in data:
                f.write(json.dumps(item, ensure_ascii=False) + "\n")
