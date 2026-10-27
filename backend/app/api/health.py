"""Health check endpoint."""
from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.database.connection import check_db_health
from app.services.model_loader import get_model
from app.services.screenshot_service import get_ocr_status

router = APIRouter(tags=["health"])


@router.get("/health")
async def health_check():
    settings = get_settings()
    model, model_err = get_model()
    ocr_available, ocr_engine, ocr_detail = get_ocr_status()
    db_ok = check_db_health()

    rep_sources = {
        "google_safe_browsing": "configured" if settings.google_safebrowsing_configured else "unconfigured",
        "urlhaus": "configured" if settings.urlhaus_configured else "unconfigured",
        "phishtank": "configured" if settings.phishtank_configured else "unconfigured",
        "openphish": "configured" if settings.openphish_configured else "unconfigured",
    }

    status = "ok" if db_ok else "degraded"
    if not db_ok:
        status = "degraded"

    return JSONResponse(
        status_code=200 if db_ok else 503,
        content={
            "status": status,
            "db": "ok" if db_ok else "error",
            "model_loaded": model is not None,
            "model_version": model.model_version if model else None,
            "model_error": model_err,
            "ocr_available": ocr_available,
            "ocr_engine": ocr_engine if ocr_available else None,
            "ocr_detail": ocr_detail,
            "external_lookups_enabled": settings.ENABLE_EXTERNAL_LOOKUPS,
            "reputation_sources": rep_sources,
            "version": "1.0.0",
        },
    )
