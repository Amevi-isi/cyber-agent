import json
import signal
import functools

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_EVENT_CHARS = 4000  # ~1 000 tokens — au-delà on tronque

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

VALID_CLASSIFICATIONS = {"benign", "suspicious", "confirmed_incident", "unknown"}
VALID_SEVERITIES = {"low", "medium", "high", "critical", "unknown"}


# ---------------------------------------------------------------------------
# Input guard
# ---------------------------------------------------------------------------

def sanitize_event(event: dict) -> dict:
    """
    Vérifie l'événement avant injection dans le prompt :
    1. Détecte les tentatives d'injection de prompt.
    2. Tronque les champs trop longs.

    Raises:
        ValueError: si une injection est détectée.
    """
    serialized = json.dumps(event, ensure_ascii=False).lower()

    for pattern in INJECTION_PATTERNS:
        if pattern in serialized:
            raise ValueError(
                f"[GUARD] Prompt injection détectée dans l'événement : '{pattern}'"
            )

    if len(serialized) > MAX_EVENT_CHARS:
        event = _truncate_event(event)

    return event


def _truncate_event(event: dict, max_field_chars: int = 500) -> dict:
    """Tronque les valeurs string dépassant max_field_chars caractères."""
    truncated = {}
    for k, v in event.items():
        if isinstance(v, str) and len(v) > max_field_chars:
            truncated[k] = v[:max_field_chars] + "...[truncated]"
        else:
            truncated[k] = v
    return truncated


# ---------------------------------------------------------------------------
# Timeout guard (Linux uniquement — utilise SIGALRM)
# ---------------------------------------------------------------------------

def with_timeout(seconds: int):
    """
    Décorateur qui lève TimeoutError si la fonction dépasse `seconds` secondes.
    Utilise signal.SIGALRM — fonctionne uniquement sur Linux/macOS.
    """
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
                signal.alarm(0)  # Annuler l'alarme quoi qu'il arrive
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Output schema validation guard
# ---------------------------------------------------------------------------

_DEFAULTS = {
    "classification": "unknown",
    "attack_type": "none",
    "mitre_tactic": "unknown",
    "mitre_technique": "unknown",
    "severity": "unknown",
    "confidence": 0,
    "event_type": "unknown",
    "affected_asset": "unknown",
    "event_time": "unknown",
    "iocs": {"ip": [], "domain": [], "hash": [], "user": []},
    "evidence_extract": "",
}


def validate_output(result: dict) -> dict:
    """
    Valide et normalise le dict retourné par le LLM :
    - Ajoute les champs manquants avec des valeurs par défaut.
    - Corrige classification et severity si hors enum.
    - Clamp confidence entre 0 et 100.
    - Assure que iocs est un dict avec les bonnes clés.
    - Ajoute un flag `_guard_*` sur chaque correction pour traçabilité.
    """
    # Champs manquants → valeurs par défaut
    for field, default in _DEFAULTS.items():
        if field not in result:
            result[field] = default
            result[f"_guard_missing_{field}"] = True

    # Classification hors enum
    if result["classification"] not in VALID_CLASSIFICATIONS:
        result["_guard_classification_original"] = result["classification"]
        result["classification"] = "unknown"

    # Severity hors enum
    if result["severity"] not in VALID_SEVERITIES:
        result["_guard_severity_original"] = result["severity"]
        result["severity"] = "unknown"

    # Confidence : doit être un entier entre 0 et 100
    try:
        result["confidence"] = max(0, min(100, int(result["confidence"])))
    except (TypeError, ValueError):
        result["_guard_confidence_original"] = result.get("confidence")
        result["confidence"] = 0

    # iocs : doit être un dict avec les 4 clés standard
    if not isinstance(result.get("iocs"), dict):
        result["_guard_iocs_original"] = result.get("iocs")
        result["iocs"] = {"ip": [], "domain": [], "hash": [], "user": []}
    else:
        for key in ["ip", "domain", "hash", "user"]:
            if not isinstance(result["iocs"].get(key), list):
                result["iocs"][key] = []

    return result
