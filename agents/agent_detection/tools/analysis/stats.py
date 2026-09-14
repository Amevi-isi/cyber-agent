# tools/analysis/stats.py

import statistics
from collections import Counter
from ..base import BaseTool


class EventStatsTool(BaseTool):
    def __init__(self):
        super().__init__("event_stats_tool")

    def run(self, events: list) -> dict:
        if not events:
            return {"total_events": 0, "event_frequency": {}, "top_source_ips": [], "anomalies": []}

        total = len(events)

        # Fréquence par source (suricata, wazuh, …)
        sources = Counter(e.get("source", "unknown") for e in events)

        # Top 5 IPs sources les plus fréquentes
        ip_counter = Counter(
            e.get("src_ip") for e in events if e.get("src_ip")
        )
        top_ips = ip_counter.most_common(5)

        # Anomalies : IPs dont le count dépasse mean + 2×stdev
        anomalies: list[str] = []
        if len(ip_counter) >= 2:
            counts = list(ip_counter.values())
            mean = statistics.mean(counts)
            stdev = statistics.stdev(counts)
            threshold = mean + 2 * stdev
            anomalies = [ip for ip, cnt in ip_counter.items() if cnt > threshold]

        return {
            "total_events": total,
            "event_frequency": dict(sources),
            "top_source_ips": [{"ip": ip, "count": cnt} for ip, cnt in top_ips],
            "anomalies": anomalies,
        }
