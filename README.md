# DZOLACYBER — SOC Multi-Agent

Plateforme SOC multi-agents pilotée par LLM, suivant le framework **NIST SP 800-61** (Incident Response).

Cinq agents spécialisés couvrent chaque phase du cycle de réponse aux incidents. Deux modes d'orchestration sont disponibles : **appels Python directs** (dev/test) ou **pipeline distribué MCP/SSE** piloté par un LLM (production). Chaque agent est protégé par une couche de **guards** : anti-injection de prompt, timeout LLM et validation du schéma de sortie.

---

## Architecture générale

```
Événement brut (Suricata / Wazuh / FortiGate / EDR / …)
        │
        ▼
┌──────────────────────────────┐
│        Orchestrateur         │
│  (SOCOrchestrator  ou  LLM)  │
└──────────────────────────────┘
        │
        ├─ [1] agent_detection      NIST: Detect    → classification, MITRE ATT&CK, IOCs, sévérité
        ├─ [2] agent_identification  NIST: Analyze   → attack chain, GeoIP, scope, timeline
        ├─ [3] agent_protection     NIST: Contain   → règles firewall, EDR, comptes à désactiver
        ├─ [4] agent_reponse        NIST: Respond   → IRIS (case) + MISP (IOCs) + FortiGate (block)
        └─ [5] agent_recuperation   NIST: Recover   → plan de restauration, leçons apprises
```

**Logique de routage :**

| Résultat de la détection | Étapes suivantes |
|---|---|
| `benign` ou `unknown` + sévérité faible | Arrêt après détection (log only) |
| `suspicious` ou `confirmed_incident` | + identification + protection |
| `confirmed_incident` + `high/critical` + confiance ≥ 60 + `AUTO_RESPOND=true` | + réponse + récupération |

---

## Modes de communication

### Mode 1 — Appels Python directs (`orchestrator.py`)

Utilisé en développement. `main.py` charge chaque agent via `importlib`, les instancie et les passe à `SOCOrchestrator`. La communication est des appels de méthodes Python en mémoire — pas de réseau.

```
event → SOCOrchestrator.process(event)
           → detection.analyze_event_detect(event)
           → identification.analyze_event_identify(...)
           → protection.recommend(...)
           → response.execute(...)
           → recuperation.plan(...)
```

### Mode 2 — MCP/SSE + LLM orchestrateur (`llm_orchestrator.py`)

Utilisé en production (Docker). Chaque agent expose un serveur **FastMCP** via SSE sur son propre port. L'orchestrateur (Claude ou Ollama avec `tool_use`) décide dynamiquement de l'ordre des étapes en appelant les agents comme des outils MCP.

```
event → LLMOrchestrator.run(event)
           → LLM (tool_use loop)
               → HTTP SSE → agent_detection:8001   detect_event()
               → HTTP SSE → agent_identification:8002   identify_incident()
               → HTTP SSE → agent_protection:8003   recommend_containment()
               → HTTP SSE → agent_reponse:8004   execute_response()
               → HTTP SSE → agent_recuperation:8005   plan_recovery()
```

| Agent | Port MCP/SSE | Outil exposé |
|---|---|---|
| `agent_detection` | `8001` | `detect_event()` |
| `agent_identification` | `8002` | `identify_incident()` |
| `agent_protection` | `8003` | `recommend_containment()` |
| `agent_reponse` | `8004` | `execute_response()` |
| `agent_recuperation` | `8005` | `plan_recovery()` |
| `orchestrator` (API HTTP) | `8080` | `POST /analyze`, `POST /analyze/batch` |

> **LLM supportés pour `tool_use` :** Claude (Anthropic) par défaut. Pour un usage 100 % local, utiliser `llama3.1` ou `qwen2.5` via Ollama (`llama3` ne supporte pas les outils).

---

## Stack technique

| Composant | Rôle | Port |
|---|---|---|
| **Ollama** (`llama3` / `llama3.1`) | LLM local | `11434` |
| **ChromaDB** | Mémoire sémantique vectorielle | `8000` |
| **Neo4j** | Corrélation graphe (entités/attaques) | `7474` (UI), `7687` (Bolt) |
| **IRIS DFIR** | Gestion des incidents / cases | `4433` |
| **MISP** | Partage de threat intelligence / IOCs | `8080` / `8443` |
| **FortiGate** | Blocage automatique d'IPs (API REST) | — |

---

## Guards & Sécurité des entrées/sorties

Chaque agent possède un `guards.py` qui applique quatre couches de protection.

### 1. `sanitize_*` — Anti-injection de prompt

Détecte 9 patterns d'injection (ex. `ignore previous instructions`, `system:`, `</s>`) et tronque les champs texte à 4 000 caractères. En cas de détection, le pipeline retourne immédiatement sans appel LLM :

```json
{ "verdict": "blocked", "pipeline_stopped_at": "input_guard" }
```

### 2. `with_timeout(seconds)` — Timeout LLM

Décorateur SIGALRM (Linux). Si le LLM dépasse `LLM_TIMEOUT_SECONDS` (défaut : 120 s), le pipeline passe au verdict `error`.

### 3. `extract_json(text)` — Parser JSON robuste

Extrait le premier bloc JSON valide d'une réponse LLM quelle que soit l'enveloppe (prose, balises markdown, chaîne de pensée).

### 4. `validate_output` — Validation du schéma de sortie

| Agent | Champs vérifiés |
|---|---|
| `agent_detection` | `classification` ∈ enum, `severity` ∈ enum, `confidence` 0–100, `iocs` dict 4 clés |
| `agent_identification` | `scope` ∈ {contained/spreading/unknown}, listes forcées |
| `agent_protection` | `urgency` ∈ {immediate/scheduled/monitor-only/unknown}, 5 listes |
| `agent_reponse` | listes d'actions, `total_success`/`total_errors` recalculés |
| `agent_recuperation` | `estimated_recovery_time` en dict `{total, by_asset}` |
| `orchestrator` | `verdict` ∈ enum, `stages` dict, 4 clés requises |

Les champs manquants sont complétés avec une valeur par défaut. Les corrections sont signalées par des flags `_guard_*` dans la sortie.

---

## Structure du projet

```
agents/
├── agent_detection/
│   ├── agent.py        # DetectionAgent.analyze_event_detect() → dict
│   ├── guards.py
│   ├── llm.py          # OllamaLLM + ClaudeLLM
│   ├── memory.py       # Memory (circulaire) + ChromaMemory (persistante)
│   ├── server.py       # FastMCP SSE — expose detect_event()
│   ├── main.py         # Exécution directe → soc_report.json
│   └── tools/
│       ├── ingestion/  # SuricataTool, WazuhTool
│       ├── enrichment/ # GeoIPTool, IOCEnrichmentTool
│       ├── analysis/   # EventStatsTool (z-score)
│       ├── correlation/ # Neo4jTool
│       └── memory/     # ChromaTool
├── agent_identification/
│   ├── agent.py        # IdentificationAgent.analyze() → dict
│   ├── server.py       # FastMCP SSE — expose identify_incident()
│   └── main.py         # → identification_report.json
├── agent_protection/
│   ├── agent.py        # ProtectionAgent.recommend() → dict
│   ├── server.py       # FastMCP SSE — expose recommend_containment()
│   └── main.py         # → protection_report.json
├── agent_reponse/
│   ├── agent.py        # ResponseAgent.execute() → dict (sans LLM)
│   ├── server.py       # FastMCP SSE — expose execute_response()
│   ├── main.py         # → response_report.json
│   └── tools/          # iris.py, misp.py, fortigate.py
├── agent_recuperation/
│   ├── agent.py        # RecuperationAgent.plan() → dict
│   ├── server.py       # FastMCP SSE — expose plan_recovery()
│   └── main.py         # → recuperation_report.json
└── orchestrator/
    ├── orchestrator.py     # SOCOrchestrator — mode Python direct
    ├── llm_orchestrator.py # LLMOrchestrator — mode MCP/SSE + tool_use
    ├── api.py              # FastAPI HTTP (POST /analyze) pour n8n
    └── main.py             # → pipeline_report.json

docker/
└── docker-compose.yml  # Neo4j, ChromaDB, Ollama, IRIS, MISP + agents MCP

dummy/                  # Générateurs de données de test synthétiques
lab/simple_agent/       # Agent minimal de référence
n8n/                    # Workflow n8n (webhook → POST /analyze)
```

---

## Installation

### Prérequis

- Python 3.11+
- Docker + Docker Compose
- Ollama (`llama3` pour les agents, `llama3.1` si `LLMOrchestrator` local)

### Dépendances Python

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### Infrastructure Docker

```bash
cd docker
docker compose --env-file ../.env up -d

# Modèle pour les agents
docker exec ollama ollama pull llama3

# Optionnel : modèle avec tool_use pour LLMOrchestrator local
docker exec ollama ollama pull llama3.1
```

### Variables d'environnement

```bash
cp .env.example .env
```

```env
# LLM
ANTHROPIC_API_KEY=...          # requis pour LLMOrchestrator avec Claude
OLLAMA_MODEL=llama3            # modèle Ollama pour les agents
LLM_TIMEOUT_SECONDS=120
LLM_TEMPERATURE=0.7
LLM_MAX_TOKENS=30000

# Agents MCP (production Docker)
AUTO_RESPOND=false
AGENT_DETECTION_URL=http://localhost:8001
AGENT_IDENTIFICATION_URL=http://localhost:8002
AGENT_PROTECTION_URL=http://localhost:8003
AGENT_RESPONSE_URL=http://localhost:8004
AGENT_RECUPERATION_URL=http://localhost:8005

# ChromaDB
CHROMA_HOST=localhost
CHROMA_PORT=8000
CHROMA_COLLECTION_NAME=soc_events

# Neo4j
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=...

# Outils de réponse
IRIS_URL=https://localhost:4433
IRIS_TOKEN=...
MISP_URL=https://localhost:8443
MISP_TOKEN=...
FORTIGATE_URL=https://fortigate.company.com
FORTIGATE_TOKEN=...
```

---

## Utilisation

### Mode développement — pipeline Python direct

```bash
cd agents/orchestrator
python main.py
# → pipeline_report.json
```

### Mode production — agents MCP/SSE

Démarrer chaque agent comme un microservice :

```bash
# Terminal par agent (ou via Docker)
cd agents/agent_detection     && python server.py   # :8001
cd agents/agent_identification && python server.py   # :8002
cd agents/agent_protection    && python server.py   # :8003
cd agents/agent_reponse       && python server.py   # :8004
cd agents/agent_recuperation  && python server.py   # :8005

# API HTTP orchestrateur (pour n8n / webhooks)
cd agents/orchestrator
uvicorn api:app --host 0.0.0.0 --port 8080
```

Puis envoyer un événement :

```bash
curl -X POST http://localhost:8080/analyze \
  -H "Content-Type: application/json" \
  -d '{"event": {"source": "wazuh", "rule": "multiple failed ssh login", "src_ip": "185.220.101.5"}}'
```

### Agents individuels (test)

```bash
cd agents/agent_detection     && python main.py   # → soc_report.json
cd agents/agent_identification && python main.py   # → identification_report.json
cd agents/agent_protection    && python main.py   # → protection_report.json
cd agents/agent_reponse       && python main.py   # → response_report.json
cd agents/agent_recuperation  && python main.py   # → recuperation_report.json
```

### Activer la réponse automatique

Via variable d'environnement (recommandé) :
```bash
AUTO_RESPOND=true uvicorn api:app --host 0.0.0.0 --port 8080
```

Ou dans `agents/orchestrator/main.py` :
```python
orchestrator = SOCOrchestrator(..., auto_respond=True)
```

---

## Exemple de sortie pipeline

```json
{
  "verdict": "confirmed_incident",
  "pipeline_stopped_at": "complete",
  "stages": {
    "detection": {
      "classification": "confirmed_incident",
      "severity": "high",
      "confidence": 85,
      "attack_type": "Brute Force",
      "mitre_tactic": "Credential Access",
      "mitre_technique": "T1110",
      "iocs": { "ips": ["185.220.101.5"], "domains": [], "hashes": [], "users": ["root"] }
    },
    "identification": {
      "scope": "contained",
      "attack_chain": ["Reconnaissance", "Credential Access"],
      "victim_assets": ["srv-auth-01"],
      "timeline": ["2026-04-10T03:12:00Z"]
    },
    "protection": {
      "urgency": "immediate",
      "ips_to_block": ["185.220.101.5"],
      "edr_isolations": ["srv-auth-01"],
      "accounts_to_disable": ["root"]
    }
  }
}
```

**En cas d'injection de prompt détectée :**

```json
{
  "verdict": "blocked",
  "pipeline_stopped_at": "input_guard",
  "_guard_input_error": "Prompt injection detected: 'ignore previous instructions'"
}
```

---

## Mémoire sémantique (ChromaDB)

Les événements analysés sont stockés dans une base vectorielle persistante (`agents/agent_detection/chroma_db/`). Lors de chaque analyse, les événements passés sémantiquement similaires sont retrouvés et injectés dans le contexte du LLM — permettant la corrélation de campagnes d'attaques (même IP, même technique, même acteur).

```python
from memory import ChromaMemory

m = ChromaMemory(collection_name="soc_events")
m.add_event({"source": "suricata", "alert": "ET SCAN Nmap", "src_ip": "10.0.0.5"})
ctx = m.get_context("Nmap scan reconnaissance")
```

---

## Sécurité

- Clés API chargées exclusivement via `.env` (`python-dotenv`) — jamais en dur
- `agent_reponse` est la **seule** couche qui exécute des actions réelles (IRIS/MISP/FortiGate)
- `AUTO_RESPOND=false` par défaut — la réponse active doit être explicitement activée
- Les agents de détection et d'identification sont **read-only**
- `LLM_TIMEOUT_SECONDS` empêche tout blocage infini sur un appel LLM lent
