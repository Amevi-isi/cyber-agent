import json
import signal
import functools

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_PAYLOAD_CHARS = 8000  # l'input est un dict de detection, peut être plus riche

def extract_json(text: str):
    """
    Extrait et parse le premier objet JSON {} ou tableau [] depuis une réponse LLM.
    Gère : blocs ```json```, texte libre autour, prose ajoutée par le modèle.
    """
    text = text.strip()

    # 1. Blocs markdown ```json ... ``` ou ``` ... ```
    if "```json" in text:
        text = text.split("```json", 1)[1].split("```", 1)[0].strip()
    elif "```" in text:
        text = text.split("```", 1)[1].split("```", 1)[0].strip()
    else:
        # 2. Recherche du premier { ou [ et du dernier } ou ]
        start_obj = text.find("{")
        start_arr = text.find("[")
        if start_obj == -1 and start_arr == -1:
            raise ValueError("Aucun JSON trouvé dans la réponse du LLM")
        if start_arr == -1 or (start_obj != -1 and start_obj < start_arr):
            end = text.rfind("}")
            text = text[start_obj : end + 1]
        else:
            end = text.rfind("]")
            text = text[start_arr : end + 1]

    return json.loads(text)


INJECTION_PATTERNS = [
    "ignore all previous",
    "disregard the above",
    "forget your instructions",
    "you are now",
    "act as if",
    "new instructions:",
    "system prompt",
    "jailbreak",
]

VALID_SCOPES = {"contained", "spreading", "unknown"}
VALID_CONFIDENCES = range(0, 101)


# ---------------------------------------------------------------------------
# Input guard
# ---------------------------------------------------------------------------

def sanitize_detection_output(detection_output: dict) -> dict:
    """
    Vérifie le dict issu de agent_detection avant injection dans le prompt :
    1. Détecte les tentatives d'injection de prompt.
    2. Tronque les champs trop longs.

    Raises:
        ValueError: si une injection est détectée.
    """
    serialized = json.dumps(detection_output, ensure_ascii=False).lower()

    for pattern in INJECTION_PATTERNS:
        if pattern in serialized:
            raise ValueError(
                f"[GUARD] Prompt injection détectée dans detection_output : '{pattern}'"
            )

    if len(serialized) > MAX_PAYLOAD_CHARS:
        detection_output = _truncate_dict(detection_output)

    return detection_output


def _truncate_dict(d: dict, max_field_chars: int = 1000) -> dict:
    truncated = {}
    for k, v in d.items():
        if isinstance(v, str) and len(v) > max_field_chars:
            truncated[k] = v[:max_field_chars] + "...[truncated]"
        else:
            truncated[k] = v
    return truncated


# ---------------------------------------------------------------------------
# Timeout guard (Linux/macOS — SIGALRM)
# ---------------------------------------------------------------------------

def with_timeout(seconds: int):
    """Décorateur timeout via SIGALRM."""
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            def _handler(signum, frame):
                raise TimeoutError(
                    f"[GUARD] {fn.__name__} a dépassé le timeout de {seconds}s"
                )
            signal.signal(signal.SIGALRM, _handler)
            signal.alarm(seconds)
            try:
                return fn(*args, **kwargs)
            finally:
                signal.alarm(0)
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Output schema validation guard
# ---------------------------------------------------------------------------

_DEFAULTS = {
    "incident_id": "INC-UNKNOWN",
    "threat_actor": "unknown",
    "scope": "unknown",
    "attack_chain": [],
    "victim_assets": [],
    "timeline": [],
    "enriched_iocs": {"ip": [], "domain": [], "hash": [], "user": []},
    "related_events": [],
    "confidence": 0,
    "analysis_summary": "",
}


def validate_output(result: dict) -> dict:
    """
    Valide et normalise le dict retourné par le LLM :
    - Ajoute les champs manquants avec des valeurs par défaut.
    - Corrige scope si hors enum.
    - Clamp confidence entre 0 et 100.
    - Ajoute un flag `_guard_*` sur chaque correction pour traçabilité.
    """
    for field, default in _DEFAULTS.items():
        if field not in result:
            result[field] = default
            result[f"_guard_missing_{field}"] = True

    # scope hors enum
    if result.get("scope") not in VALID_SCOPES:
        result["_guard_scope_original"] = result.get("scope")
        result["scope"] = "unknown"

    # confidence : entier 0–100
    try:
        result["confidence"] = max(0, min(100, int(result["confidence"])))
    except (TypeError, ValueError):
        result["_guard_confidence_original"] = result.get("confidence")
        result["confidence"] = 0

    # enriched_iocs : doit être un dict avec les 4 clés standard
    if not isinstance(result.get("enriched_iocs"), dict):
        result["_guard_enriched_iocs_original"] = result.get("enriched_iocs")
        result["enriched_iocs"] = {"ip": [], "domain": [], "hash": [], "user": []}
    else:
        for key in ["ip", "domain", "hash", "user"]:
            if not isinstance(result["enriched_iocs"].get(key), list):
                result["enriched_iocs"][key] = []

    # attack_chain, victim_assets, timeline, related_events → doivent être des listes
    for list_field in ["attack_chain", "victim_assets", "timeline", "related_events"]:
        if not isinstance(result.get(list_field), list):
            result[f"_guard_{list_field}_original"] = result.get(list_field)
            result[list_field] = []

    return result
