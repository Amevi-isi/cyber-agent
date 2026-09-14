from datetime import datetime, timedelta
from typing import List, Dict, Any


class TimelineCorrelator:
    """Ensures temporal consistency across all generated events."""

    def __init__(self):
        self.events = []

    def add_event(self, event: dict, source: str, timestamp: str = None):
        """Add an event to the timeline."""
        if timestamp is None:
            timestamp = event.get("timestamp") or event.get("event_time") or event.get("TimeCreated")
        
        self.events.append({
            "event": event,
            "source": source,
            "timestamp": timestamp
        })

    def sort_by_timestamp(self):
        """Sort events by timestamp."""
        self.events.sort(key=lambda x: x["timestamp"])

    def get_sorted_events(self) -> List[dict]:
        """Get events sorted by timestamp."""
        self.sort_by_timestamp()
        return [e["event"] for e in self.events]

    def get_events_by_source(self, source: str) -> List[dict]:
        """Get events from a specific source."""
        return [e["event"] for e in self.events if e["source"] == source]

    def get_time_range(self) -> tuple:
        """Get the time range of events."""
        if not self.events:
            return None, None
        
        timestamps = [datetime.fromisoformat(e["timestamp"].replace('Z', '+00:00')) for e in self.events if e["timestamp"]]
        if not timestamps:
            return None, None
            
        return min(timestamps), max(timestamps)


class IOCCorrelator:
    """Correlates IOCs across different sources."""

    def __init__(self):
        self.iocs = {}

    def add_ioc(self, ioc_type: str, ioc_value: str, source: str, event: dict):
        """Add an IOC to the correlator."""
        if ioc_type not in self.iocs:
            self.iocs[ioc_type] = {}
        
        if ioc_value not in self.iocs[ioc_type]:
            self.iocs[ioc_type][ioc_value] = []
        
        self.iocs[ioc_type][ioc_value].append({
            "source": source,
            "event": event
        })

    def find_matches(self, ioc_type: str, ioc_value: str) -> List[dict]:
        """Find all matches for an IOC."""
        if ioc_type not in self.iocs:
            return []
        return self.iocs.get(ioc_type, {}).get(ioc_value, [])

    def get_all_iocs(self) -> Dict[str, Dict[str, List[dict]]]:
        """Get all IOCs."""
        return self.iocs


class AssetCorrelator:
    """Maps assets to events."""

    def __init__(self):
        self.asset_events = {}

    def add_asset_event(self, asset_id: str, event: dict, timestamp: str = None):
        """Add an event for an asset."""
        if asset_id not in self.asset_events:
            self.asset_events[asset_id] = []
        
        self.asset_events[asset_id].append({
            "event": event,
            "timestamp": timestamp
        })

    def get_asset_events(self, asset_id: str) -> List[dict]:
        """Get all events for an asset."""
        return self.asset_events.get(asset_id, [])

    def get_all_assets(self) -> List[str]:
        """Get all asset IDs."""
        return list(self.asset_events.keys())
