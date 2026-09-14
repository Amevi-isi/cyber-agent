"""
Ingestion script — charge les données dummy dans Neo4j et ChromaDB.

Usage :
    python ingest.py

Variables d'environnement (optionnelles) :
    NEO4J_URI      bolt://localhost:7687
    NEO4J_USER     neo4j
    NEO4J_PASSWORD testpassword
    CHROMA_HOST    localhost
    CHROMA_PORT    8000
"""

import json
import os
import uuid
from pathlib import Path

from neo4j import GraphDatabase
import chromadb

# ─── Configuration ────────────────────────────────────────────────────────────
DATA_DIR = Path(__file__).parent.parent / "dummy" / "data"

NEO4J_URI      = os.getenv("NEO4J_URI",      "bolt://localhost:7687")
NEO4J_USER     = os.getenv("NEO4J_USER",     "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "testpassword")

CHROMA_HOST = os.getenv("CHROMA_HOST", "localhost")
CHROMA_PORT = int(os.getenv("CHROMA_PORT", "8000"))

BATCH_SIZE = 200  # taille des batchs Neo4j

# ─── Helpers ──────────────────────────────────────────────────────────────────

def load_jsonl(path: Path) -> list[dict]:
    events = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def batched(iterable, size):
    for i in range(0, len(iterable), size):
        yield iterable[i : i + size]


# ─── Neo4j ingestion ─────────────────────────────────────────────────────────

def neo4j_ingest(driver):
    print("\n── Neo4j ──────────────────────────────────────────────────")

    with driver.session() as session:
        # Contraintes d'unicité (idempotentes)
        for constraint in [
            "CREATE CONSTRAINT ip_unique IF NOT EXISTS FOR (n:IP) REQUIRE n.address IS UNIQUE",
            "CREATE CONSTRAINT host_unique IF NOT EXISTS FOR (n:Host) REQUIRE n.name IS UNIQUE",
            "CREATE CONSTRAINT user_unique IF NOT EXISTS FOR (n:User) REQUIRE n.name IS UNIQUE",
            "CREATE CONSTRAINT ioc_unique IF NOT EXISTS FOR (n:IOC) REQUIRE n.value IS UNIQUE",
            "CREATE CONSTRAINT process_unique IF NOT EXISTS FOR (n:Process) REQUIRE n.name IS UNIQUE",
        ]:
            session.run(constraint)

    # ── Suricata : IP → IP + Alert ─────────────────────────────────────────
    suricata = load_jsonl(DATA_DIR / "suricata_events.jsonl")
    print(f"  Suricata : {len(suricata)} events")
    for batch in batched(suricata, BATCH_SIZE):
        with driver.session() as session:
            session.run(
                """
                UNWIND $rows AS e
                MERGE (src:IP {address: e.src_ip})
                MERGE (dst:IP {address: e.dest_ip})
                MERGE (src)-[r:CONNECTED_TO {
                    src_port:  e.src_port,
                    dst_port:  e.dest_port,
                    proto:     e.proto,
                    timestamp: e.timestamp
                }]->(dst)
                WITH src, dst, e
                WHERE e.alert IS NOT NULL
                MERGE (a:Alert {
                    signature_id: e.alert.signature_id,
                    signature:    e.alert.signature
                })
                ON CREATE SET a.category = e.alert.category,
                              a.severity = e.alert.severity
                MERGE (a)-[:TRIGGERED_BETWEEN]->(src)
                MERGE (a)-[:TRIGGERED_BETWEEN]->(dst)
                """,
                rows=batch,
            )
    print("    ✓ IP→IP + Alert nodes")

    # ── Wazuh : Alert → Host ───────────────────────────────────────────────
    wazuh = load_jsonl(DATA_DIR / "wazuh_alerts.jsonl")
    print(f"  Wazuh : {len(wazuh)} events")
    for batch in batched(wazuh, BATCH_SIZE):
        with driver.session() as session:
            session.run(
                """
                UNWIND $rows AS e
                MERGE (h:Host {name: e.agent.name})
                  ON CREATE SET h.agent_id = e.agent.id,
                                h.ip       = e.agent.ip
                MERGE (a:Alert {
                    signature_id: e.rule.id,
                    signature:    e.rule.description
                })
                  ON CREATE SET a.severity = e.rule.level,
                                a.groups   = e.rule.groups
                MERGE (a)-[:TRIGGERED_ON]->(h)
                WITH h, e
                WHERE e.data.srcip IS NOT NULL
                MERGE (src:IP {address: e.data.srcip})
                MERGE (src)-[:ATTACKED]->(h)
                """,
                rows=batch,
            )
    print("    ✓ Alert→Host + IP→Host")

    # ── Fortigate : IP → IP (flux réseau) ─────────────────────────────────
    fortigate = load_jsonl(DATA_DIR / "fortigate_logs.jsonl")
    print(f"  Fortigate : {len(fortigate)} events")
    for batch in batched(fortigate, BATCH_SIZE):
        with driver.session() as session:
            session.run(
                """
                UNWIND $rows AS e
                MERGE (src:IP {address: e.srcip})
                MERGE (dst:IP {address: e.dstip})
                MERGE (src)-[r:NETWORK_FLOW {
                    src_port:  e.srcport,
                    dst_port:  e.dstport,
                    action:    e.action,
                    service:   e.service,
                    timestamp: e.date + 'T' + e.time + 'Z'
                }]->(dst)
                WITH src, e
                WHERE e.user IS NOT NULL AND e.user <> ''
                MERGE (u:User {name: e.user})
                MERGE (u)-[:GENERATED_FLOW]->(src)
                """,
                rows=batch,
            )
    print("    ✓ IP→IP flux Fortigate + User→IP")

    # ── AD Events : User → Host ────────────────────────────────────────────
    ad = load_jsonl(DATA_DIR / "ad_events.jsonl")
    print(f"  AD Events : {len(ad)} events")
    for batch in batched(ad, BATCH_SIZE):
        with driver.session() as session:
            session.run(
                """
                UNWIND $rows AS e
                MERGE (u:User {name: e.TargetUserName + '@' + e.TargetDomainName})
                  ON CREATE SET u.sid = e.TargetUserSid
                MERGE (h:Host {name: e.Computer})
                MERGE (u)-[r:LOGGED_INTO {
                    event_id:  e.EventID,
                    logon_type: e.LogonType,
                    timestamp: e.TimeCreated,
                    auth:      e.AuthenticationPackageName
                }]->(h)
                WITH u, e
                WHERE e.IpAddress IS NOT NULL
                MERGE (ip:IP {address: e.IpAddress})
                MERGE (ip)-[:USED_BY]->(u)
                """,
                rows=batch,
            )
    print("    ✓ User→Host (AD logons)")

    # ── EDR : Process → Host + Process → IOC ──────────────────────────────
    edr = load_jsonl(DATA_DIR / "edr_events.jsonl")
    print(f"  EDR : {len(edr)} events")
    for batch in batched(edr, BATCH_SIZE):
        with driver.session() as session:
            session.run(
                """
                UNWIND $rows AS e
                MERGE (h:Host {name: e.hostname})
                MERGE (p:Process {name: e.process_name})
                  ON CREATE SET p.path = e.process_path
                MERGE (p)-[r:EXECUTED_ON {
                    event_type: e.event_type,
                    pid:        e.process_id,
                    severity:   e.severity,
                    tactic:     e.tactic,
                    technique:  e.technique,
                    timestamp:  e.event_time
                }]->(h)
                WITH h, p, e
                WHERE e.file_hash_sha256 IS NOT NULL
                MERGE (ioc:IOC {value: e.file_hash_sha256})
                  ON CREATE SET ioc.type = 'sha256'
                MERGE (p)-[:MATCHES_IOC]->(ioc)
                """,
                rows=batch,
            )
    print("    ✓ Process→Host + Process→IOC (EDR)")

    # ── MISP IOCs ──────────────────────────────────────────────────────────
    with open(DATA_DIR / "misp_iocs.json", encoding="utf-8") as f:
        misp = json.load(f)
    print(f"  MISP IOCs : {len(misp)} entries")
    for batch in batched(misp, BATCH_SIZE):
        with driver.session() as session:
            session.run(
                """
                UNWIND $rows AS e
                MERGE (ioc:IOC {value: e.Attribute.value})
                  ON CREATE SET
                    ioc.type      = e.Attribute.type,
                    ioc.category  = e.Attribute.category,
                    ioc.comment   = e.Attribute.comment,
                    ioc.event_id  = e.Event.id,
                    ioc.event_info = e.Event.info,
                    ioc.threat_level = e.Event.threat_level_id,
                    ioc.source    = e.Event.Org.name
                """,
                rows=batch,
            )
    print("    ✓ IOC nodes (MISP)")

    print("  Neo4j ingestion terminée ✓")


# ─── ChromaDB ingestion ───────────────────────────────────────────────────────

def chroma_ingest(client: chromadb.HttpClient):
    print("\n── ChromaDB ───────────────────────────────────────────────")

    col = client.get_or_create_collection("soc_events")

    def add_batch(docs: list[str], ids: list[str], metas: list[dict]):
        col.add(documents=docs, ids=ids, metadatas=metas)

    # ── Suricata ───────────────────────────────────────────────────────────
    suricata = load_jsonl(DATA_DIR / "suricata_events.jsonl")
    print(f"  Suricata : {len(suricata)} events")
    for batch in batched(suricata, BATCH_SIZE):
        docs, ids, metas = [], [], []
        for e in batch:
            alert = e.get("alert", {})
            text = (
                f"[Suricata] {e.get('timestamp','')} "
                f"{e.get('src_ip','')}:{e.get('src_port','')} -> "
                f"{e.get('dest_ip','')}:{e.get('dest_port','')} "
                f"proto={e.get('proto','')} "
                f"signature='{alert.get('signature','')}' "
                f"category='{alert.get('category','')}' "
                f"action={alert.get('action','')} severity={alert.get('severity','')}"
            )
            docs.append(text)
            ids.append(f"suricata_{e.get('flow_id', str(uuid.uuid4()))}")
            metas.append({
                "source": "suricata",
                "timestamp": e.get("timestamp", ""),
                "src_ip": e.get("src_ip", ""),
                "severity": str(alert.get("severity", "")),
            })
        add_batch(docs, ids, metas)
    print("    ✓ Suricata embedé")

    # ── Wazuh ──────────────────────────────────────────────────────────────
    wazuh = load_jsonl(DATA_DIR / "wazuh_alerts.jsonl")
    print(f"  Wazuh : {len(wazuh)} events")
    for batch in batched(wazuh, BATCH_SIZE):
        docs, ids, metas = [], [], []
        for e in batch:
            rule = e.get("rule", {})
            agent = e.get("agent", {})
            text = (
                f"[Wazuh] {e.get('timestamp','')} "
                f"agent={agent.get('name','')} "
                f"rule='{rule.get('description','')}' "
                f"level={rule.get('level','')} "
                f"mitre={rule.get('mitre',[])} "
                f"log='{e.get('full_log','')}'"
            )
            docs.append(text)
            ids.append(f"wazuh_{agent.get('id','x')}_{e.get('timestamp','').replace(':','-').replace(' ','_')}_{str(uuid.uuid4())[:8]}")
            metas.append({
                "source": "wazuh",
                "timestamp": e.get("timestamp", ""),
                "agent_name": agent.get("name", ""),
                "rule_level": str(rule.get("level", "")),
            })
        add_batch(docs, ids, metas)
    print("    ✓ Wazuh embedé")

    # ── Ukweli (sandbox analysis) ──────────────────────────────────────────
    ukweli = load_jsonl(DATA_DIR / "ukweli_analysis.jsonl")
    print(f"  Ukweli sandbox : {len(ukweli)} entries")
    for batch in batched(ukweli, BATCH_SIZE):
        docs, ids, metas = [], [], []
        for e in batch:
            text = (
                f"[Sandbox] {e.get('submission_date','')} "
                f"file={e.get('file_name','')} "
                f"verdict={e.get('verdict','')} "
                f"score={e.get('detection_score','')} "
                f"malware_family={e.get('malware_family','')} "
                f"behaviors={e.get('behavior_summary',[])} "
                f"sha256={e.get('sha256','')}"
            )
            docs.append(text)
            ids.append(f"ukweli_{e.get('submission_id', str(uuid.uuid4()))}")
            metas.append({
                "source": "ukweli",
                "timestamp": e.get("submission_date", ""),
                "verdict": e.get("verdict", ""),
                "malware_family": str(e.get("malware_family", "")),
            })
        add_batch(docs, ids, metas)
    print("    ✓ Ukweli embedé")

    # ── EDR ────────────────────────────────────────────────────────────────
    edr = load_jsonl(DATA_DIR / "edr_events.jsonl")
    print(f"  EDR : {len(edr)} events")
    for batch in batched(edr, BATCH_SIZE):
        docs, ids, metas = [], [], []
        for e in batch:
            text = (
                f"[EDR] {e.get('event_time','')} "
                f"host={e.get('hostname','')} "
                f"user={e.get('username','')} "
                f"process={e.get('process_name','')} "
                f"event_type={e.get('event_type','')} "
                f"tactic={e.get('tactic','')} technique={e.get('technique','')} "
                f"severity={e.get('severity','')}"
            )
            docs.append(text)
            ids.append(f"edr_{e.get('aid', str(uuid.uuid4()))}_{e.get('event_time','').replace(':','-').replace(' ','_')}_{str(uuid.uuid4())[:8]}")
            metas.append({
                "source": "edr",
                "timestamp": e.get("event_time", ""),
                "hostname": e.get("hostname", ""),
                "severity": e.get("severity", ""),
            })
        add_batch(docs, ids, metas)
    print("    ✓ EDR embedé")

    total = col.count()
    print(f"  ChromaDB total documents : {total} ✓")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("=== Ingestion démarrée ===")

    # Neo4j
    neo_driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    try:
        neo4j_ingest(neo_driver)
    finally:
        neo_driver.close()

    # ChromaDB
    chroma_client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)
    chroma_ingest(chroma_client)

    print("\n=== Ingestion terminée ✓ ===")


if __name__ == "__main__":
    main()
