# Quick Fix Guide - Critical Issues First

## 🔴 CRITICAL FIXES (Do these immediately)

### 1. Create Missing chroma.py File
**Impact:** ChromaMemory will crash on first use
```bash
# Create: /agents/agent_detection/tools/memory/chroma.py
```
Expected to contain `ChromaTool` class that wraps ChromaDB collection operations.

### 2. Create Missing __init__.py Files
```bash
touch /agents/agent_detection/tools/__init__.py
touch /agents/agent_detection/tools/correlation/__init__.py
touch /agents/agent_detection/tools/memory/__init__.py
touch /agents/agent_detection/tools/ingestion/__init__.py
touch /agents/agent_detection/tools/analysis/__init__.py
touch /agents/agent_detection/tools/enrichment/__init__.py
```

### 3. Fix orchestrator/main.py - Add Neo4j to Detection Agent
**File:** `/agents/orchestrator/main.py` Line 84
**Current:**
```python
detection_agent = DetectionAgent(llm, detection_memory)
```
**Should be:**
```python
# First add Neo4jTool instantiation (after line 63):
neo4j = Neo4jTool(
    uri=os.getenv("NEO4J_URI", "bolt://localhost:7687"),
    user=os.getenv("NEO4J_USER", "neo4j"),
    password=os.getenv("NEO4J_PASSWORD", "testpassword"),
)

# Then pass to agent (line 84):
detection_agent = DetectionAgent(llm, detection_memory, neo4j_tool=neo4j)
```

### 4. Fix sys.modules Guard Namespace Pollution
**File:** `/agents/orchestrator/main.py` Lines 48-92
**Problem:** Each agent's guards module overwrites sys.modules["guards"]
**Solution:** Use qualified module names:
```python
def _load_agent_class(agent_folder: str, class_name: str):
    agent_dir = agents_root / agent_folder
    guards_file = agent_dir / "guards.py"
    
    # Use agent-specific name, don't override global 'guards'
    guards_mod_name = f"{agent_folder}_guards"
    if guards_file.exists():
        guards_mod = _load_module(guards_mod_name, guards_file)
        # Temporarily set as 'guards' ONLY during agent import
        sys.modules["guards"] = guards_mod
    
    # Import agent
    sys.path.insert(0, str(agent_dir))
    module_name = f"{agent_folder}_agent"
    spec = importlib.util.spec_from_file_location(module_name, agent_dir / "agent.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    
    # Restore separate guards in sys.modules
    if guards_file.exists():
        sys.modules[guards_mod_name] = guards_mod
        # Clean up the temporary 'guards' reference
        if "guards" in sys.modules and sys.modules["guards"] == guards_mod:
            del sys.modules["guards"]
    
    return getattr(mod, class_name)
```

### 5. Fix Collection Name Fragmentation
**Issue:** Detection uses "soc_events", Identification uses "soc_incidents"
**File:** `/agents/agent_detection/main.py` Line 11
**And:** `/agents/agent_identification/main.py` Line 24
**And:** `/agents/orchestrator/main.py` Line 76

**Make consistent:**
```python
# All should use same collection name
collection_name = os.getenv("CHROMA_COLLECTION_NAME", "soc_events")

# agent_detection/main.py:
memory = ChromaMemory(collection_name=collection_name, ...)

# agent_identification/main.py:
memory = ChromaMemory(collection_name=collection_name, ...)

# orchestrator/main.py:
detection_memory = ChromaMemory(collection_name=collection_name, ...)
```

---

## 🟡 HIGH PRIORITY FIXES (Within this sprint)

### 6. Standardize LLM Temperature
All agents except Detection use 0.7. Detection uses 0.1.
**File:** `/agents/agent_detection/main.py` Line 19
**Change:**
```python
# FROM:
llm = OllamaLLM(model='llama3', max_tokens=4096, temperature=0.1)

# TO:
temperature = float(os.getenv("LLM_TEMPERATURE", "0.7"))
llm = OllamaLLM(model='llama3', max_tokens=4096, temperature=temperature)
```

### 7. Increase Detection Agent max_tokens
Detection limited to 4096, should be 30000 like others
**File:** `/agents/agent_detection/main.py` Line 19
**Change:**
```python
# FROM:
llm = OllamaLLM(model='llama3', max_tokens=4096, temperature=0.1)

# TO:
max_tokens = int(os.getenv("LLM_MAX_TOKENS", "30000"))
llm = OllamaLLM(model='llama3', max_tokens=max_tokens, temperature=0.7)
```

### 8. Add Tool Initialization Validation
**Files:** 
- `/agents/agent_reponse/tools/iris.py` __init__
- `/agents/agent_reponse/tools/misp.py` __init__
- `/agents/agent_reponse/tools/fortigate.py` __init__

**Add validation pattern:**
```python
def __init__(self, base_url: str = None, api_key: str = None, verify_ssl: bool = True):
    self.base_url = (base_url or os.getenv("IRIS_URL", "")).rstrip("/")
    self.api_key = api_key or os.getenv("IRIS_TOKEN", "")
    self.verify_ssl = verify_ssl
    
    # ADD THIS:
    if not self.base_url:
        raise ValueError("IRIS_URL environment variable not set")
    if not self.api_key:
        raise ValueError("IRIS_TOKEN environment variable not set")
    
    self._session = requests.Session()
    ...
```

### 9. Fix neo4j filename typo
**Current:** `/agents/agent_detection/tools/correlation/ne4j.py` (missing 'o')
**Action:** Rename to `neo4j.py`
**Update imports:** Already correct - `from tools.correlation.ne4j import Neo4jTool`

### 10. Make FortiGate Group Name Configurable
**File:** `/agents/agent_reponse/tools/fortigate.py`
**Add to __init__:**
```python
self.blocklist_group = os.getenv("FORTIGATE_BLOCKLIST_GROUP", "SOC_BLOCKLIST")
```
**Update line 37:**
```python
# FROM:
self._request("POST", "/firewall/addrgrp/SOC_BLOCKLIST/member", {

# TO:
self._request("POST", f"/firewall/addrgrp/{self.blocklist_group}/member", {
```

---

## 🟠 MEDIUM PRIORITY (This quarter)

### 11. Remove unused analyze_event() from Detection Agent
**File:** `/agents/agent_detection/agent.py` Lines 26-52
- Two very similar methods: `analyze_event()` and `analyze_event_detect()`
- Only `analyze_event_detect()` is used (has Neo4j enrichment)
- Decision: Keep `analyze_event_detect()`, remove `analyze_event()`

### 12. Add GeoIP Caching
**File:** `/agents/agent_detection/tools/enrichment/geoip.py`
- Current: Every IP looked up fresh each time
- Add: Local cache (file or dict) with TTL
- Benefit: Faster and won't get rate-limited

### 13. Fix Memory.get_context() Query Usage
**File:** `/agents/agent_detection/memory.py` Lines 19-22
- Simple Memory class ignores query parameter
- ChromaMemory class uses it for semantic search
- **Option A:** Rename methods to avoid confusion (Memory.get_all(), ChromaMemory.get_context())
- **Option B:** Make Memory.get_context() behavior consistent

### 14. Add ChromaDB Connection Check on Init
**File:** `/agents/agent_detection/memory.py` __init__
```python
def __init__(self, ...):
    ...
    self.collection = self.client.get_or_create_collection(collection_name)
    # ADD THIS:
    try:
        self.collection.count()  # Test connection
    except Exception as e:
        raise ConnectionError(f"Failed to connect to ChromaDB: {e}")
```

### 15. Lazy-load Claude import
**File:** `/agents/agent_detection/llm.py` Line 1
- Move `import anthropic` inside `ClaudeLLM.__init__()` 
- None of the agents actually use Claude currently
- Benefit: Anthropic package no longer required if not using Claude

---

## 📋 TESTING CHECKLIST

After fixes, test:

- [ ] ChromaMemory initialization doesn't crash
- [ ] Detection agent receives Neo4j tool in orchestrator
- [ ] All imports resolve (no ModuleNotFoundError)
- [ ] Guard functions called from correct module
- [ ] Detection and Identification share same ChromaDB collection
- [ ] LLM parameters consistent across agents
- [ ] Tool initialization fails gracefully if env vars missing
- [ ] Orchestrator pipeline completes end-to-end

---

## FILE DEPENDENCY GRAPH

```
orchestrator/main.py
├── agent_detection/ (imports)
│   ├── memory.py (needs tools/memory/chroma.py)
│   ├── llm.py
│   ├── agent.py (uses DetectionAgent)
│   ├── guards.py
│   ├── tools/
│   │   ├── correlation/ne4j.py (MISSING __init__.py)
│   │   ├── enrichment/geoip.py
│   │   └── memory/ (MISSING __init__.py and chroma.py)
│   └── tools/ingestion/ (MISSING __init__.py)
│
├── agent_identification/
│   ├── memory.py (from agent_detection, different collection)
│   ├── agent.py (uses IdentificationAgent)
│   └── guards.py (imports extract_json from guards)
│
├── agent_protection/
│   ├── memory.py (from agent_detection)
│   ├── agent.py
│   └── guards.py
│
├── agent_recuperation/
│   ├── memory.py (from agent_detection)
│   ├── agent.py
│   └── guards.py
│
├── agent_reponse/
│   ├── memory.py (from agent_detection)
│   ├── agent.py
│   ├── guards.py
│   └── tools/
│       ├── iris.py (needs IRIS_URL validation)
│       ├── misp.py (needs MISP_URL validation)
│       └── fortigate.py (needs FORTIGATE_URL validation)
│
└── orchestrator/
    └── guards.py
```

