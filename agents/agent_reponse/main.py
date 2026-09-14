import sys
import os
import json
import importlib.util
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

HERE = Path(__file__).parent
agents_root = HERE.parent

# agent_detection en priorité pour Memory, LLM, et son package tools/
sys.path.insert(0, str(agents_root / "agent_detection"))

from memory import Memory
from llm import build_llm

# Charger ResponseAgent via importlib pour éviter le conflit tools/ namespace
def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod

_guards = _load("guards",        HERE / "guards.py")   # doit être "guards" pour que agent.py le trouve
_agent  = _load("reponse_agent", HERE / "agent.py")
_iris   = _load("reponse_iris",   HERE / "tools" / "iris.py")
_misp   = _load("reponse_misp",   HERE / "tools" / "misp.py")
_fg     = _load("reponse_fg",     HERE / "tools" / "fortigate.py")

ResponseAgent  = _agent.ResponseAgent
IRISTool       = _iris.IRISTool
MISPTool       = _misp.MISPTool
FortiGateTool  = _fg.FortiGateTool

# ── Setup ──────────────────────────────────────────────────────────────────────
# Les outils se configurent via les variables d'environnement :
#   IRIS_URL + IRIS_TOKEN
#   MISP_URL + MISP_TOKEN
#   FORTIGATE_URL + FORTIGATE_TOKEN
llm = build_llm()
memory = Memory()

iris = IRISTool()         # None → désactiver si IRIS_URL vide
misp = MISPTool()         # None → désactiver si MISP_URL vide
fortigate = FortiGateTool()  # None → désactiver si FORTIGATE_URL vide

agent = ResponseAgent(llm, memory, iris=iris, misp=misp, fortigate=fortigate)

# ── Test: exécution sur un scénario de réponse ────────────────────────────────
identification_output = {
    "incident_id": "INC-AUTO",
    "threat_actor": "unknown",
    "scope": "contained",
    "analysis_summary": "Brute force SSH depuis Tor exit node 185.220.101.5 ciblant root@server1.",
    "enriched_iocs": {
        "ip": [{"ip": "185.220.101.5", "type": "public", "country": "Germany"}],
        "domain": [],
        "hash": [],
        "user": ["root"],
    },
    "confidence": 85,
}

protection_output = {
    "urgency": "immediate",
    "firewall_rules": [
        {"action": "block", "direction": "inbound", "src_ip": "185.220.101.5",
         "protocol": "tcp", "dst_port": 22, "reason": "Tor exit node brute forcing SSH"},
    ],
    "edr_actions": [],
    "account_actions": [],
}

report = agent.execute(protection_output, identification_output)

if __name__ == "__main__":
    output_path = Path(__file__).parent / "response_report.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"Rapport écrit dans {output_path}")
