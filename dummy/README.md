# Dummy Data Generator - Documentation

> Générateur de données synthétiques réalistes pour DzolaCyber

## Table des matières

1. [Vue d'ensemble](#vue-densemble)
2. [Architecture](#architecture)
3. [Installation](#installation)
4. [Utilisation](#utilisation)
5. [Configuration](#configuration)
6. [Structure du code](#structure-du-code)
7. [Ajouter un nouveau générateur](#ajouter-un-nouveau-générateur)
8. [Couche données (dictionnaires)](#couche-données-dictionnaires)
9. [Dépannage](#dépannage)

---

## Vue d'ensemble

Le module `dummy/` génère des données de sécurité synthétiques réalistes pour tester l'Agent Orchestrateur DzolaCyber dans un environnement de développement/test.

### Sources de données simulées

| Source | Type | Format |
|--------|------|--------|
| **Wazuh** | Alertes EDR/SIEM | JSONL |
| **Suricata** | Events IDS/IPS | JSONL |
| **FortiGate** | Logs pare-feu | JSONL |
| **Active Directory** | Events Windows | JSONL |
| **EDR** | Events endpoint | JSONL |
| **MISP** | IOCs threat intelligence | JSON |
| **IRIS** | Cas d'investigation | JSON |
| **UKWELI** | Analyses sandbox | JSONL |
| **Assets** | Inventaire CMDB | JSON |
| **Users** | Annuaire utilisateurs | JSON |

---

## Architecture

```
dummy/
├── config/                 # Fichiers de configuration YAML
│   ├── config.yaml        # Configuration principale
│   ├── scenarios.yaml     # Définitions des scénarios d'attaque
│   └── sources.yaml       # Schémas des sources de données
├── data/
│   ├── dictionaries/      # Données réalistes (noms, IPs, règles...)
│   └── templates/        # Modèles JSON par source
├── generators/            # Générateurs par source
│   ├── base_generator.py # Classe de base
│   └── [source]_generator.py
├── correlators/          # Corrélation entre sources
├── exporters/            # Export JSON/JSONL
├── main.py              # Point d'entrée
└── requirements.txt     # Dépendances
```

### Flux de données

```
Config YAML → Générateurs → Données → Exporteurs → Fichiers JSON/JSONL
                ↑
         Dictionnaires
```

---

## Installation

```bash
# Installer depuis la racine
pip install pyyaml
```

---

## Utilisation

### Génération standard

```bash
cd dummy
python main.py
```

Les données sont générées dans `dummy/data/`.

### Avec configuration personnalisée

```python
from main import load_config, generate_assets, generate_internal_sources

config = load_config("chemin/vers/config.yaml")
assets, users, asset_gen = generate_assets(config)
internal = generate_internal_sources(config, asset_gen)
```

---

## Configuration

### Fichier `config.yaml`

```yaml
dummy:
  time_range:
    start: "2026-03-05T00:00:00Z"
    end: "2026-03-05T23:59:59Z"
  
  volume:
    wazuh_alerts_per_day: 100
    suricata_events_per_hour: 100
    misp_iocs_total: 100
    # ...
  
  output:
    format: "jsonl"
    path: "dummy/data"

sources:
  assets:
    server_count: 30
    workstation_count: 70
  users:
    total_count: 150
    privileged_ratio: 0.1
```

### Volume recommandé par environnement

| Environnement | wazuh/jour | suricata/heure |
|---------------|------------|-----------------|
| Dev | 100 | 100 |
| Test | 1 000 | 1 000 |
| Prod (simulé) | 5 000+ | 5 000+ |

---

## Structure du code

### Classe de base `BaseGenerator`

Tous les générateurs héritent de `BaseGenerator` qui fournit:

```python
class BaseGenerator:
    def __init__(self, config: dict = None)
    def _load_dictionaries(self)  # Charge les dictionnaires
    def random_ip(self, private: bool = True) -> str
    def random_external_ip(self) -> str
    def random_port(self) -> int
    def random_timestamp(self, start=None, end=None) -> str
    def uuid4(self) -> str
    def generate_mac(self) -> str
```

### Méthodes obligatoires

Chaque générateur doit implémenter:

```python
def generate_event(self, timestamp: str = None, event_type: str = None) -> dict:
    """Génère un événement unique."""

def generate_events(self, count: int, start=None, end=None) -> list:
    """Génère plusieurs événements."""
    
def generate_events_for_scenario(self, events: list, base_time: datetime) -> list:
    """Génère des événements pour un scénario spécifique."""
```

---

## Ajouter un nouveau générateur

### 1. Créer le fichier

`dummy/generators/nouveau_generator.py`:

```python
import logging
import random
from datetime import datetime, timedelta
from .base_generator import BaseGenerator

logger = logging.getLogger("dummy.generator.nouveau")

class NouveauGenerator(BaseGenerator):
    """Générateur pour [nom de la source]."""

    def __init__(self, config: dict = None):
        super().__init__(config)
        # Initialisation spécifique
        self._load_signatures()

    def _load_signatures(self):
        """Charger les données spécifiques."""
        # Charger depuis les dictionnaires
        self.data = self.get_dict("ma_donnee", [])

    def generate_event(self, timestamp: str = None, event_type: str = None) -> dict:
        """Génère un événement unique."""
        if timestamp is None:
            timestamp = self.random_timestamp()
        
        return {
            "timestamp": timestamp,
            # ... champs spécifiques
        }

    def generate_events(self, count: int = 100, start: datetime = None, end: datetime = None) -> list:
        """Génère plusieurs événements."""
        events = []
        for _ in range(count):
            timestamp = self.random_timestamp(start, end)
            events.append(self.generate_event(timestamp))
        return events
```

### 2. Mettre à jour les imports

`dummy/generators/__init__.py`:

```python
try:
    from .nouveau_generator import NouveauGenerator
except ImportError:
    NouveauGenerator = None
```

### 3. Ajouter au main.py

```python
from generators import NouveauGenerator

# Dans generate_internal_sources ou generate_external_sources
nouveau_gen = NouveauGenerator(config)
nouveau_events = nouveau_gen.generate_events(count, start, end)
exporter_jsonl.export(nouveau_events, "nouveau_events.jsonl")
```

### 4. Ajouter un dictionnaire

`dummy/data/dictionnaires/nouveau_data.json`:

```json
{
  "items": [
    {"id": 1, "name": "Item 1"},
    {"id": 2, "name": "Item 2"}
  ]
}
```

---

## Couche données (dictionnaires)

Les dictionnaires sont stockés dans `dummy/data/dictionnaires/` et chargés automatiquement par `BaseGenerator`.

### Dictionnaires existants

| Fichier | Contenu |
|---------|---------|
| `hostnames.json` | Noms d'hôtes, ranges IP |
| `users.json` | Prénoms, noms, départements, groupes |
| `wazuh_rules.json` | Règles Wazuh, groupes MITRE |
| `suricata_signatures.json` | Signatures Suricata |
| `misc.json` | Familles malware, acteurs APT, techniques MITRE |

### Ajouter des données

1. Créer ou modifier un fichier JSON dans `dictionnaires/`
2. Utiliser `self.get_dict("clé")` dans le générateur

```python
# Exemple
hostnames = self.get_dict("hostnames", ["default_host"])
malware_families = self.get_dict("malware_families", [])
```

---

## Dépannage

### Les dictionnaires ne se chargent pas

Vérifier le chemin:
```python
dict_dir = Path(__file__).parent.parent / "data" / "dictionaries"
```

### La génération est lente

- Réduire les volumes dans `config.yaml`
- Vérifier que `random.sample` n'est pas utilisé (utiliser `random.choices`)

### Erreur "Expression of type None cannot be assigned"

C'est un warning LSP (type checking). Le code fonctionne mais les types ne sont pas déclarés. Utiliser:
```python
def func(self, param: dict = None):
    param = param or {}
```

### Les dates sont incorrectes

Vérifier que `random_timestamp` reçoit des objets `datetime`:
```python
start = datetime.fromisoformat(time_range.get("start").replace('Z', '+00:00'))
end = datetime.fromisoformat(time_range.get("end").replace('Z', '+00:00'))
```

---

## Contribution

Pour ajouter une fonctionnalité:

1. Créer une branche `feature/nom-feature`
2. Implémenter dans un nouveau générateur ou modifier existant
3. Tester avec des volumes réduits
4. Mettre à jour la documentation

### Convention de nommage

- Fichiers: `snake_case.py`
- Classes: `PascalCase`
- Méthodes: `snake_case()`
- Logs: `logger = logging.getLogger("dummy.generator.nom")`
