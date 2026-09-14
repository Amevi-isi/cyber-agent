# tools/correlation/neo4j_tool.py

from neo4j import GraphDatabase
from ..base import BaseTool


class Neo4jTool(BaseTool):
    def __init__(self, uri, user, password):
        super().__init__("neo4j_tool")
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def run(self, query: str):
        with self.driver.session() as session:
            result = session.run(query)
            return [r.data() for r in result]

    def get_event_context(self, event: dict) -> dict:
        """
        Enrichit un événement avec le contexte graphe Neo4j :
        - alertes connues sur les IPs impliquées
        - historique de connexions de l'IP source
        - IOCs matchant les hashes ou IPs de l'événement
        - activité passée de l'utilisateur
        """
        ctx = {
            "known_alerts": [],
            "ip_connections": [],
            "matching_iocs": [],
            "user_activity": [],
        }

        # Extraire les champs utiles selon la source de l'événement
        src_ip = (
            event.get("src_ip")
            or event.get("srcip")
            or event.get("local_address")
        )
        hostname = (
            event.get("agent", {}).get("name") if isinstance(event.get("agent"), dict)
            else event.get("hostname")
        )
        username = (
            event.get("username")
            or (event.get("data", {}).get("user") if isinstance(event.get("data"), dict) else None)
        )
        file_hash = event.get("file_hash_sha256")

        with self.driver.session() as session:

            # 1. Alertes associées à l'IP source
            if src_ip:
                res = session.run(
                    """
                    MATCH (a:Alert)-[:TRIGGERED_BETWEEN]->(ip:IP {address: $ip})
                    RETURN a.signature AS signature, a.category AS category, a.severity AS severity
                    LIMIT 5
                    """,
                    ip=src_ip,
                )
                ctx["known_alerts"] = [r.data() for r in res]

            # 2. Connexions passées depuis cette IP
            if src_ip:
                res = session.run(
                    """
                    MATCH (src:IP {address: $ip})-[r:CONNECTED_TO]->(dst:IP)
                    RETURN dst.address AS dest_ip, r.proto AS proto,
                           r.dst_port AS dst_port, r.timestamp AS timestamp
                    ORDER BY r.timestamp DESC LIMIT 5
                    """,
                    ip=src_ip,
                )
                ctx["ip_connections"] = [r.data() for r in res]

            # 3. IOCs matchant hash ou IP
            ioc_value = file_hash or src_ip
            if ioc_value:
                res = session.run(
                    """
                    MATCH (ioc:IOC {value: $val})
                    RETURN ioc.value AS value, ioc.type AS type,
                           ioc.event_info AS event_info, ioc.threat_level AS threat_level
                    LIMIT 3
                    """,
                    val=ioc_value,
                )
                ctx["matching_iocs"] = [r.data() for r in res]

            # 4. Activité passée de l'utilisateur
            if username:
                res = session.run(
                    """
                    MATCH (u:User)-[r:LOGGED_INTO]->(h:Host)
                    WHERE u.name CONTAINS $user
                    RETURN h.name AS host, r.timestamp AS timestamp,
                           r.logon_type AS logon_type, r.auth AS auth
                    ORDER BY r.timestamp DESC LIMIT 5
                    """,
                    user=username,
                )
                ctx["user_activity"] = [r.data() for r in res]

        return ctx