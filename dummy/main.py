#!/usr/bin/env python3
"""
Dummy Data Generator for DzolaCyber
Generates realistic synthetic security data for testing the orchestration agent.
"""

import logging
import os
import sys
import json
import yaml
import random
from datetime import datetime, timedelta
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)-8s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("dummy")

sys.path.insert(0, str(Path(__file__).parent))

logger.info("Importing generators...")

from generators import (
    AssetGenerator, WazuhGenerator, SuricataGenerator, 
    FortiGateGenerator, ADGenerator, EDRGenerator,
    MISPGenerator, IRISGenerator, UKWELIGenerator
)
logger.info("Generators imported successfully")

from exporters import JSONExporter, JSONLExporter
logger.info("Exporters imported successfully")


def load_config(config_path: str = None) -> dict:
    """Load configuration from YAML file."""
    if config_path is None:
        config_path = Path(__file__).parent / "config" / "config.yaml"
    
    logger.info(f"Loading config from: {config_path}")
    
    if not Path(config_path).exists():
        logger.warning(f"Config file not found: {config_path}, using defaults")
        return get_default_config()
    
    with open(config_path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)
    logger.info("Config loaded successfully")
    return config


def get_default_config() -> dict:
    """Get default configuration."""
    return {
        "dummy": {
            "time_range": {
                "start": "2026-03-05T00:00:00Z",
                "end": "2026-03-05T23:59:59Z"
            },
            "volume": {
                "wazuh_alerts_per_day": 1000,
                "suricata_events_per_hour": 5000,
                "misp_iocs_total": 10000,
                "iris_cases": 50,
                "fortigate_logs_per_hour": 3000,
                "ad_events_per_hour": 2000,
                "edr_events_per_hour": 4000,
                "ukweli_analyses": 100
            },
            "output": {
                "format": "jsonl",
                "path": "dummy/data"
            }
        }
    }


def generate_assets(config: dict) -> tuple:
    """Generate asset inventory and users."""
    logger.info("Generating assets...")
    
    asset_gen = AssetGenerator(config)
    
    sources = config.get("sources", {})
    assets_config = sources.get("assets", {})
    users_config = sources.get("users", {})
    
    servers = assets_config.get("server_count", 30)
    workstations = assets_config.get("workstation_count", 70)
    users = users_config.get("total_count", 150)
    privileged_ratio = users_config.get("privileged_ratio", 0.1)
    
    logger.info(f"Generating {servers} servers, {workstations} workstations, {users} users")
    
    assets = asset_gen.generate_assets(servers, workstations)
    users_data = asset_gen.generate_users(users, privileged_ratio)
    
    logger.info(f"  Generated {len(assets)} assets")
    logger.info(f"  Generated {len(users_data)} users")
    
    return assets, users_data, asset_gen


def generate_internal_sources(config: dict, asset_gen: AssetGenerator):
    """Generate internal security sources."""
    logger.info("Generating internal sources...")
    
    volume = config.get("dummy", {}).get("volume", {})
    output_path = config.get("dummy", {}).get("output", {}).get("path", "dummy/data")
    
    exporter_json = JSONExporter(output_path)
    exporter_jsonl = JSONLExporter(output_path)
    
    time_range = config.get("dummy", {}).get("time_range", {})
    start = datetime.fromisoformat(time_range.get("start", "2026-03-05T00:00:00Z").replace('Z', '+00:00'))
    end = datetime.fromisoformat(time_range.get("end", "2026-03-05T23:59:59Z").replace('Z', '+00:00'))
    
    wazuh_count = volume.get("wazuh_alerts_per_day", 1000)
    logger.info(f"  Generating {wazuh_count} Wazuh alerts...")
    wazuh_gen = WazuhGenerator(config, asset_gen)
    wazuh_alerts = wazuh_gen.generate_alerts(wazuh_count, start, end)
    exporter_jsonl.export(wazuh_alerts, "wazuh_alerts.jsonl")
    
    suricata_count = volume.get("suricata_events_per_hour", 5000) * 24
    logger.info(f"  Generating {suricata_count} Suricata events...")
    suricata_gen = SuricataGenerator(config)
    suricata_events = suricata_gen.generate_events(suricata_count, start, end)
    exporter_jsonl.export(suricata_events, "suricata_events.jsonl")
    
    fortigate_count = volume.get("fortigate_logs_per_hour", 3000) * 24
    logger.info(f"  Generating {fortigate_count} FortiGate logs...")
    fortigate_gen = FortiGateGenerator(config)
    fortigate_logs = fortigate_gen.generate_logs(fortigate_count, start, end)
    exporter_jsonl.export(fortigate_logs, "fortigate_logs.jsonl")
    
    ad_count = volume.get("ad_events_per_hour", 2000) * 24
    logger.info(f"  Generating {ad_count} AD events...")
    ad_gen = ADGenerator(config)
    ad_events = ad_gen.generate_events(ad_count, start, end)
    exporter_jsonl.export(ad_events, "ad_events.jsonl")
    
    edr_count = volume.get("edr_events_per_hour", 4000) * 24
    logger.info(f"  Generating {edr_count} EDR events...")
    edr_gen = EDRGenerator(config)
    edr_events = edr_gen.generate_events(edr_count, start, end)
    exporter_jsonl.export(edr_events, "edr_events.jsonl")
    
    return {
        "wazuh": wazuh_alerts,
        "suricata": suricata_events,
        "fortigate": fortigate_logs,
        "ad": ad_events,
        "edr": edr_events
    }


def generate_external_sources(config: dict):
    """Generate external threat intelligence sources."""
    logger.info("Generating external sources...")
    
    volume = config.get("dummy", {}).get("volume", {})
    output_path = config.get("dummy", {}).get("output", {}).get("path", "dummy/data")
    
    exporter_json = JSONExporter(output_path)
    exporter_jsonl = JSONLExporter(output_path)
    
    time_range = config.get("dummy", {}).get("time_range", {})
    start = datetime.fromisoformat(time_range.get("start", "2026-03-05T00:00:00Z").replace('Z', '+00:00'))
    end = datetime.fromisoformat(time_range.get("end", "2026-03-05T23:59:59Z").replace('Z', '+00:00'))
    
    misp_count = volume.get("misp_iocs_total", 10000)
    logger.info(f"  Generating {misp_count} MISP IOCs...")
    misp_gen = MISPGenerator(config)
    misp_iocs = misp_gen.generate_iocs(misp_count, start - timedelta(days=30), end)
    exporter_json.export(misp_iocs, "misp_iocs.json")
    
    iris_count = volume.get("iris_cases", 50)
    logger.info(f"  Generating {iris_count} IRIS cases...")
    iris_gen = IRISGenerator(config)
    iris_cases = iris_gen.generate_cases(iris_count, start - timedelta(days=90), end)
    exporter_json.export(iris_cases, "iris_cases.json")
    
    ukweli_count = volume.get("ukweli_analyses", 100)
    logger.info(f"  Generating {ukweli_count} UKWELI analyses...")
    ukweli_gen = UKWELIGenerator(config)
    ukweli_analyses = ukweli_gen.generate_submissions(ukweli_count, start - timedelta(days=30), end)
    exporter_jsonl.export(ukweli_analyses, "ukweli_analysis.jsonl")
    
    return {
        "misp": misp_iocs,
        "iris": iris_cases,
        "ukweli": ukweli_analyses
    }


def generate_metadata(config: dict, assets: list, users: list, internal: dict, external: dict):
    """Generate metadata file."""
    logger.info("Generating metadata...")
    
    output_path = config.get("dummy", {}).get("output", {}).get("path", "dummy/data")
    exporter_json = JSONExporter(output_path)
    
    metadata = {
        "generation_time": datetime.utcnow().isoformat() + "Z",
        "config": config,
        "statistics": {
            "assets": len(assets),
            "users": len(users),
            "wazuh_alerts": len(internal.get("wazuh", [])),
            "suricata_events": len(internal.get("suricata", [])),
            "fortigate_logs": len(internal.get("fortigate", [])),
            "ad_events": len(internal.get("ad", [])),
            "edr_events": len(internal.get("edr", [])),
            "misp_iocs": len(external.get("misp", [])),
            "iris_cases": len(external.get("iris", [])),
            "ukweli_analyses": len(external.get("ukweli", []))
        }
    }
    
    exporter_json.export(metadata, "metadata.json")
    logger.info("  Metadata generated")


def main():
    """Main entry point."""
    logger.info("=" * 60)
    logger.info("DzolaCyber - Dummy Data Generator")
    logger.info("=" * 60)
    
    config = load_config()
    
    assets, users, asset_gen = generate_assets(config)
    
    internal = generate_internal_sources(config, asset_gen)
    
    external = generate_external_sources(config)
    
    generate_metadata(config, assets, users, internal, external)
    
    output_dir = config.get("dummy", {}).get("output", {}).get("path", "dummy/data")
    logger.info("=" * 60)
    logger.info("Data generation complete!")
    logger.info(f"Output directory: {output_dir}")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
