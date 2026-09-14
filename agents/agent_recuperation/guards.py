import json
import signal
import functools

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_PAYLOAD_CHARS = 8000

INJECTION_PATTERNS = [
    "ignore previous instructions",
    "ignore all previous",
    "disregard the above",
    "forget your instructions",
    "you are now",
    "act as if",
    "new instructions:",
    "system prompt",
    "jailbreak",
]


# ---------------------------------------------------------------------------
# JSON extractor
# ---------------------------------------------------------------------------

def extract_json(text: str):
    """
    Extrait et parse le premier objet JSON {} ou tableau [] depuis une réponse LLM.
    Gère : blocs ```json```, texte libre autour, prose ajoutée par le modèle.
    """
    text = text.strip()

    if "```json" in text:
        text = text.split("```json", 1)[1].split("```", 1)[0].strip()
    elif "```" in text:
        text = text.split("```", 1)[1].split("```", 1)[0].strip()
    else:
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


# ---------------------------------------------------------------------------
# Input guards
# ---------------------------------------------------------------------------

def sanitize_input(data: dict, label: str) -> dict:
    """
    Vérifie un dict entrant avant injection dans le prompt :
    1. Détecte les tentatives d'injection de prompt.
    2. Tronque les champs trop longs.

    Raises:
        ValueError: si une injection est détectée.
    """
    serialized = json.dumps(data, ensure_ascii=False).lower()

    for pattern in INJECTION_PATTERNS:
        if pattern in serialized:
            raise ValueError(
                f"[GUARD] Prompt injection détectée dans {label} : '{pattern}'"
            )

    if len(serialized) > MAX_PAYLOAD_CHARS:
        data = _truncate_dict(data)

    return data


def _truncate_dict(d: dict, max_field_chars: int = 1000) -> dict:
    truncated = {}
    for k, v in d.items():
        if isinstance(v, str) and len(v) > max_field_chars:
            truncated[k] = v[:max_field_chars] + "...[truncated]"
        else:
            truncated[k] = v
    return truncated


# ---------------------------------------------------------------------------
# Timeout guard
# ---------------------------------------------------------------------------

def with_timeout(seconds: int):
    """Décorateur timeout via SIGALRM (Linux/macOS)."""
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
    "restoration_checklist": [],
    "eradication_steps": [],
    "verification_steps": [],
    "monitoring_recommendations": [],
    "estimated_recovery_time": {"total": "TBD", "by_asset": []},
    "lessons_learned": {"what_worked": [], "what_failed": [], "improvements": []},
    "recovery_summary": "",
}


def validate_output(result: dict) -> dict:
    """
    Valide et normalise le dict retourné par le LLM.
    Complète les champs manquants, force les listes,
    et ajoute des flags _guard_* pour traçabilité.
    """
    for field, default in _DEFAULTS.items():
        if field not in result:
            result[field] = default
            result[f"_guard_missing_{field}"] = True

    # Champs qui doivent être des listes
    for list_field in ["restoration_checklist", "eradication_steps",
                       "verification_steps", "monitoring_recommendations"]:
        if not isinstance(result.get(list_field), list):
            result[f"_guard_{list_field}_original"] = result.get(list_field)
            result[list_field] = []

    # estimated_recovery_time doit être un dict
    if not isinstance(result.get("estimated_recovery_time"), dict):
        result["_guard_ert_original"] = result.get("estimated_recovery_time")
        result["estimated_recovery_time"] = {"total": "TBD", "by_asset": []}

    # lessons_learned doit être un dict avec les 3 clés
    ll = result.get("lessons_learned", {})
    if not isinstance(ll, dict):
        result["_guard_lessons_learned_original"] = ll
        result["lessons_learned"] = {"what_worked": [], "what_failed": [], "improvements": []}
    else:
        for key in ["what_worked", "what_failed", "improvements"]:
            if not isinstance(ll.get(key), list):
                ll[key] = []

    return result
