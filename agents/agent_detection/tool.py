# A. Log ingestion (OBLIGATOIRE)

# B. Pattern / IOC detection


# C. Threat Intelligence lookup

# D. Anomaly detection (simple ML ou stats)

# 🖥️ E. System monitoring


# F. File integrity check

def get_suricata_events(filters: dict) -> list:
    """Fetch alerts from Suricata logs or EVE JSON
    Extrait :

    src_ip / dst_ip

    signature

    protocol
    """
    pass

def get_wazuh_events(query: str) -> list:
    """Query Wazuh indexer (Elastic-like)

    Exemple :

    auth logs

    sysmon

    file integrity
    """
    pass

def enrich_ioc(ioc: str) -> dict:
    """Check IP/domain/hash reputation
    Peut utiliser :

    VirusTotal

    AbuseIPDB
    """
    pass


def get_ip_context(ip: str) -> dict:
    """Geo + ASN + org"""
    pass

def search_similar_events(event: str) -> list:
    """Semantic similarity search in Chroma DB

    permet :

    détection comportementale

    réutilisation de cas passés
    """
    pass

def query_attack_graph(entity: str) -> dict:
    """Find relationships: IP → user → host → attack
    exemple :

    même IP sur plusieurs machines

    user compromis sur plusieurs endpoints
    """
    pass

def get_event_timeline(asset: str, time_window: str) -> list:
    """Retrieve related events over time"""
    pass

def detect_frequency_anomaly(events: list) -> bool:
    """Detect unusual spikes (e.g. brute force)"""
    pass

"""
Event →
  → Extract IOCs
    → enrich_ioc()
    → get_ip_context()
  → Query history
    → search_similar_events()
    → get_event_timeline()
  → Correlate
    → query_attack_graph()
→ LLM analysis
"""

