"""
FastAPI — SOC Orchestrator HTTP API

Point d'entrée HTTP pour n8n (et tout autre système externe).
Reçoit des événements de sécurité bruts et les traite via le LLM Orchestrateur.

Endpoints:
    POST /analyze          — Analyser un événement unique
    POST /analyze/batch    — Analyser un lot d'événements
    GET  /health           — Healthcheck

Usage:
    uvicorn api:app --host 0.0.0.0 --port 8080
    # Ou via docker-compose (service soc_orchestrator)
"""
import asyncio
import os
import logging
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from llm_orchestrator import LLMOrchestrator

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("soc_api")

# ── FastAPI app ────────────────────────────────────────────────────────────────
app = FastAPI(
    title="SOC DZOLACYBER — Orchestrator API",
    description=(
        "API HTTP du SOC DZOLACYBER.\n\n"
        "Reçoit des événements de sécurité bruts (Wazuh, Suricata, FortiGate, …) "
        "et les traite via le LLM Orchestrateur (Claude + agents MCP).\n\n"
        "Conçue pour être appelée par n8n (webhook → POST /analyze)."
    ),
    version="1.0.0",
)

# Instance partagée de l'orchestrateur (initialisée au démarrage)
_orchestrator: LLMOrchestrator | None = None


@app.on_event("startup")
async def _startup():
    global _orchestrator
    auto_respond = os.getenv("AUTO_RESPOND", "false").lower() == "true"
    _orchestrator = LLMOrchestrator(auto_respond=auto_respond)
    logger.info("LLMOrchestrator initialized (auto_respond=%s)", auto_respond)


# ── Modèles Pydantic ──────────────────────────────────────────────────────────
class AnalyzeRequest(BaseModel):
    event: dict = Field(
        ...,
        description="Événement de sécurité brut (Wazuh, Suricata, FortiGate, EDR, …)",
        examples=[{
            "source": "wazuh",
            "rule": "multiple failed ssh login",
            "agent": "server1",
            "src_ip": "185.220.101.5",
            "user": "root",
            "timestamp": "2026-04-02T10:23:11Z",
            "attempts": 47,
        }],
    )
    auto_respond: bool | None = Field(
        default=None,
        description=(
            "Surcharger AUTO_RESPOND pour cet événement uniquement. "
            "Si None, utilise la valeur globale de la variable d'environnement."
        ),
    )


class BatchAnalyzeRequest(BaseModel):
    events: list[dict] = Field(
        ...,
        description="Liste d'événements de sécurité bruts à analyser séquentiellement",
        min_length=1,
        max_length=50,
    )
    auto_respond: bool | None = Field(default=None)


class AnalyzeResponse(BaseModel):
    event: dict
    stages_executed: list[str]
    stages: dict
    final_analysis: str
    auto_respond: bool
    verdict: str | None = None


# ── Endpoints ─────────────────────────────────────────────────────────────────
@app.get("/health", tags=["system"])
async def health():
    """Healthcheck — retourne 200 si le service est opérationnel."""
    return {"status": "ok", "service": "soc_orchestrator"}


@app.post(
    "/analyze",
    response_model=AnalyzeResponse,
    status_code=status.HTTP_200_OK,
    tags=["soc"],
    summary="Analyser un événement de sécurité",
)
async def analyze(req: AnalyzeRequest):
    """
    Reçoit un événement de sécurité brut et exécute le pipeline SOC complet.

    Claude (LLM) décide dynamiquement des étapes à exécuter selon les résultats :
    - `detect_event` → toujours exécuté
    - `identify_incident` → si suspicious ou confirmed_incident
    - `recommend_containment` → si identification effectuée
    - `execute_response` → si auto_respond=true + severity high/critical + confidence≥60
    - `plan_recovery` → si response executée

    Conçu pour être appelé depuis n8n via webhook.
    """
    if _orchestrator is None:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")

    # Surcharge auto_respond si spécifié dans la requête
    if req.auto_respond is not None:
        orch = LLMOrchestrator(auto_respond=req.auto_respond)
    else:
        orch = _orchestrator

    try:
        logger.info("Analyzing event from source: %s", req.event.get("source", "unknown"))
        result = await orch.run(req.event)

        # Extraire le verdict de la détection
        result["verdict"] = (
            result.get("stages", {})
            .get("detect_event", {})
            .get("classification", "unknown")
        )
        return result
    except Exception as exc:
        logger.error("Pipeline error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Pipeline error: {exc}")


@app.post(
    "/analyze/batch",
    response_model=list[AnalyzeResponse],
    status_code=status.HTTP_200_OK,
    tags=["soc"],
    summary="Analyser un lot d'événements",
)
async def analyze_batch(req: BatchAnalyzeRequest):
    """
    Analyse un lot d'événements séquentiellement.
    Maximum 50 événements par appel.
    """
    if _orchestrator is None:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")

    orch = (
        LLMOrchestrator(auto_respond=req.auto_respond)
        if req.auto_respond is not None
        else _orchestrator
    )

    results = []
    for event in req.events:
        try:
            result = await orch.run(event)
            result["verdict"] = (
                result.get("stages", {})
                .get("detect_event", {})
                .get("classification", "unknown")
            )
            results.append(result)
        except Exception as exc:
            logger.error("Pipeline error for event %s: %s", event.get("source"), exc)
            results.append({
                "event": event,
                "stages_executed": [],
                "stages": {},
                "final_analysis": "",
                "auto_respond": orch.auto_respond,
                "verdict": "error",
                "error": str(exc),
            })
    return results


# ── Point d'entrée ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("ORCHESTRATOR_PORT", "8080"))
    uvicorn.run("api:app", host="0.0.0.0", port=port, reload=False)
