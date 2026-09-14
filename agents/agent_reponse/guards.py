import json

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
# Input guards
# ---------------------------------------------------------------------------

def sanitize_input(data: dict, label: str) -> dict:
    """
    Vérifie un dict entrant avant utilisation dans execute() :
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
# Output validation guard
# ---------------------------------------------------------------------------

def validate_report(report: dict) -> dict:
    """
    Valide le rapport d'exécution retourné par execute() :
    - Assure que les champs requis sont présents.
    - Assure que les compteurs sont cohérents avec les listes.
    - Ajoute un flag _guard_* sur chaque correction.
    """
    # Champs requis avec valeurs par défaut
    defaults = {
        "actions_executed": [],
        "errors": [],
        "total_success": 0,
        "total_errors": 0,
    }
    for field, default in defaults.items():
        if field not in report:
            report[field] = default
            report[f"_guard_missing_{field}"] = True

    # Forcer les listes
    for list_field in ["actions_executed", "errors"]:
        if not isinstance(report.get(list_field), list):
            report[f"_guard_{list_field}_original"] = report.get(list_field)
            report[list_field] = []

    # Recalculer les totaux si incohérents
    actual_success = len(report["actions_executed"])
    actual_errors = len(report["errors"])
    if report["total_success"] != actual_success:
        report["_guard_total_success_corrected"] = report["total_success"]
        report["total_success"] = actual_success
    if report["total_errors"] != actual_errors:
        report["_guard_total_errors_corrected"] = report["total_errors"]
        report["total_errors"] = actual_errors

    return report
