import json

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_EVENT_CHARS = 4000

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
# Input guard (événement brut entrant dans le pipeline)
# ---------------------------------------------------------------------------

def sanitize_event(event: dict) -> dict:
    """
    Vérifie l'événement brut avant de le passer au pipeline.
    Raises ValueError si une injection est détectée.
    """
    serialized = json.dumps(event, ensure_ascii=False).lower()

    for pattern in INJECTION_PATTERNS:
        if pattern in serialized:
            raise ValueError(
                f"[GUARD] Prompt injection détectée dans l'événement : '{pattern}'"
            )

    if len(serialized) > MAX_EVENT_CHARS:
        event = _truncate_dict(event)

    return event


def _truncate_dict(d: dict, max_field_chars: int = 500) -> dict:
    truncated = {}
    for k, v in d.items():
        if isinstance(v, str) and len(v) > max_field_chars:
            truncated[k] = v[:max_field_chars] + "...[truncated]"
        else:
            truncated[k] = v
    return truncated


# ---------------------------------------------------------------------------
# Output validation guard (rapport final du pipeline)
# ---------------------------------------------------------------------------

_REQUIRED_KEYS = {"event", "stages", "pipeline_stopped_at", "verdict"}

VALID_VERDICTS = {
    "benign", "suspicious", "confirmed_incident", "unknown", "blocked", "error"
}


def validate_pipeline_report(report: dict) -> dict:
    """
    Valide le rapport final du pipeline :
    - Assure que les clés requises sont présentes.
    - Corrige verdict si hors enum.
    - Ajoute des flags _guard_* pour traçabilité.
    """
    for key in _REQUIRED_KEYS:
        if key not in report:
            report[key] = None
            report[f"_guard_missing_{key}"] = True

    if report.get("verdict") not in VALID_VERDICTS:
        report["_guard_verdict_original"] = report.get("verdict")
        report["verdict"] = "unknown"

    if not isinstance(report.get("stages"), dict):
        report["_guard_stages_original"] = report.get("stages")
        report["stages"] = {}

    return report
