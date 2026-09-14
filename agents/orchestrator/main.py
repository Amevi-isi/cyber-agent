"""
Point d'entrée de l'orchestrateur SOC DZOLACYBER.

Usage:
    cd agents/orchestrator
    python main.py

Variables d'environnement (.env à la racine du repo ou dans ce dossier):
    ANTHROPIC_API_KEY  — clé Claude (si utilisé)
    IRIS_URL + IRIS_TOKEN
    MISP_URL + MISP_TOKEN
    FORTIGATE_URL + FORTIGATE_TOKEN
"""
import sys
import os
import json
import importlib.util
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

agents_root = Path(__file__).parent.parent


# ── Loader utilitaire ──────────────────────────────────────────────────────────
def _load_module(unique_name: str, file_path: Path):
    spec = importlib.util.spec_from_file_location(unique_name, file_path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[unique_name] = mod
    spec.loader.exec_module(mod)
    return mod


def _load_agent_class(agent_folder: str, class_name: str):
    """
    Charge une classe d'agent depuis son fichier agent.py.
    Charge d'abord guards.py avec un nom unique pour éviter le conflit
    de namespace 'guards' entre les agents.
    """
    agent_dir = agents_root / agent_folder

    # 1. Charger guards.py avec nom unique ET l'enregistrer sous 'guards'
    #    pour que agent.py le trouve avec 'from guards import ...'
    guards_file = agent_dir / "guards.py"
    if guards_file.exists():
        guards_mod = _load_module(f"{agent_folder}_guards", guards_file)
        sys.modules["guards"] = guards_mod

    # 2. Charger agent.py avec son dossier dans sys.path
    sys.path.insert(0, str(agent_dir))
    module_name = f"{agent_folder}_module"
    spec = importlib.util.spec_from_file_location(module_name, agent_dir / "agent.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)

    return getattr(mod, class_name)


# ── Shared: LLM + Memory (depuis agent_detection) ─────────────────────────────
sys.path.insert(0, str(agents_root / "agent_detection"))

from memory import Memory, ChromaMemory  # noqa: E402
from llm import build_llm               # noqa: E402

llm = build_llm()

# ChromaMemory se connecte à l'instance Docker ChromaDB (via HttpClient)
detection_memory = ChromaMemory(
    collection_name=os.getenv("CHROMA_COLLECTION_NAME", "soc_events"),
    chroma_host=os.getenv("CHROMA_HOST", "localhost"),
    chroma_port=int(os.getenv("CHROMA_PORT", "8000")),
)
shared_memory = Memory()  # Mémoire légère pour les autres agents

# ── GeoIP (depuis agent_detection) ────────────────────────────────────────────
from tools.enrichment.geoip import GeoIPTool  # noqa: E402

geoip = GeoIPTool()

# ── Neo4j Graph Database (pour corrélation) ──────────────────────────────────
from tools.correlation.ne4j import Neo4jTool  # noqa: E402

neo4j = Neo4jTool(
    uri=os.getenv("NEO4J_URI", "bolt://localhost:7687"),
    user=os.getenv("NEO4J_USER", "neo4j"),
    password=os.getenv("NEO4J_PASSWORD", "testpassword"),
)

# ── Tools agent_reponse ───────────────────────────────────────────────────────────
_reponse_tools = agents_root / "agent_reponse" / "tools"
iris_mod = _load_module("reponse_iris", _reponse_tools / "iris.py")
misp_mod = _load_module("reponse_misp", _reponse_tools / "misp.py")
fg_mod   = _load_module("reponse_fortigate", _reponse_tools / "fortigate.py")

IRISTool       = iris_mod.IRISTool
MISPTool       = misp_mod.MISPTool
FortiGateTool  = fg_mod.FortiGateTool

iris = IRISTool()
misp = MISPTool()
fortigate = FortiGateTool()

# ── Instanciation des agents ───────────────────────────────────────────────────
DetectionAgent = _load_agent_class("agent_detection", "DetectionAgent")
IdentificationAgent = _load_agent_class("agent_identification", "IdentificationAgent")
ProtectionAgent = _load_agent_class("agent_protection", "ProtectionAgent")
ResponseAgent = _load_agent_class("agent_reponse", "ResponseAgent")
RecuperationAgent = _load_agent_class("agent_recuperation", "RecuperationAgent")

detection_agent = DetectionAgent(llm, detection_memory, neo4j_tool=neo4j)
identification_agent = IdentificationAgent(llm, shared_memory, geoip_tool=geoip)
protection_agent = ProtectionAgent(llm, shared_memory)
response_agent = ResponseAgent(llm, shared_memory, iris=iris, misp=misp, fortigate=fortigate)
recuperation_agent = RecuperationAgent(llm, shared_memory)

# ── Charger guards de l'orchestrateur puis l'orchestrateur lui-même ──────────────
_orch_dir = Path(__file__).parent
_orch_guards = _load_module("orchestrator_guards", _orch_dir / "guards.py")
sys.modules["guards"] = _orch_guards
sys.path.insert(0, str(_orch_dir))
from orchestrator import SOCOrchestrator  # noqa: E402

orchestrator = SOCOrchestrator(
    detection_agent=detection_agent,
    identification_agent=identification_agent,
    protection_agent=protection_agent,
    response_agent=response_agent,
    recuperation_agent=recuperation_agent,
    auto_respond=False,  # Passer à True pour exécuter IRIS/MISP/FortiGate automatiquement
)

# ── Événements de test ─────────────────────────────────────────────────────────
events = [
    {
        "source": "wazuh",
        "rule": "multiple failed ssh login",
        "agent": "server1",
        "src_ip": "185.220.101.5",
        "user": "root",
        "timestamp": "2026-04-02T10:23:11Z",
        "attempts": 47,
    },
    {
        "source": "suricata",
        "alert": "ET MALWARE CnC Beacon",
        "src_ip": "192.168.1.42",
        "dest_ip": "185.220.101.5",
        "dest_port": 443,
        "severity": 1,
        "timestamp": "2026-04-02T10:30:00Z",
    },
]

results = []
for event in events:
    print("\n" + "=" * 70)
    print(f"Processing: {event.get('alert') or event.get('rule')}")
    print("=" * 70)
    report = orchestrator.process(event)
    results.append(report)
    print(f"  → verdict: {report.get('verdict')} | stopped at: {report.get('pipeline_stopped_at')}")

if __name__ == "__main__":
    output_path = Path(__file__).parent / "pipeline_report.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\nRapport écrit dans {output_path}")
