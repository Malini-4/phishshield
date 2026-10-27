"""URL analysis API routes."""
from __future__ import annotations

import hashlib
import logging
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.auth.dependencies import get_optional_user
from app.database.connection import get_db_dependency
from app.database.repository import save_investigation
from app.services.url_service import UrlAnalysisService

router = APIRouter(tags=["url"])
logger = logging.getLogger(__name__)

_service = UrlAnalysisService()


class UrlAnalyzeRequest(BaseModel):
    url: str


@router.post("/analyze")
async def analyze_url(
    request: UrlAnalyzeRequest,
    db: Session = Depends(get_db_dependency),
    current_user: Optional[dict] = Depends(get_optional_user),
):
    """Analyse a URL for phishing/malicious indicators."""
    url = request.url.strip()
    if not url:
        raise HTTPException(
            status_code=422,
            detail={"error": {"code": "EMPTY_INPUT", "message": "URL cannot be empty."}},
        )
    if len(url) > 2048:
        raise HTTPException(
            status_code=422,
            detail={"error": {"code": "TOO_LONG", "message": "URL exceeds 2048 characters."}},
        )

    t_start = time.perf_counter()

    try:
        result, url_details = await _service.analyse(url, db)
    except ValueError as e:
        raise HTTPException(
            status_code=422,
            detail={"error": {"code": "INVALID_URL", "message": str(e)}},
        )
    except Exception as e:
        logger.error(f"URL analysis error: {e}")
        raise HTTPException(
            status_code=500,
            detail={"error": {"code": "ANALYSIS_ERROR", "message": "Analysis failed unexpectedly."}},
        )

    duration_ms = int((time.perf_counter() - t_start) * 1000)
    input_hash = hashlib.sha256(url.encode()).hexdigest()
    user_id = current_user["id"] if current_user else None

    inv_id = save_investigation(db, result, url_details, duration_ms, input_hash, user_id=user_id)
    result.saved = inv_id is not None

    return result.model_dump()
