"""SMS analysis API routes."""
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
from app.services.sms_service import SmsAnalysisService

router = APIRouter(tags=["sms"])
logger = logging.getLogger(__name__)
_service = SmsAnalysisService()


class SmsAnalyzeRequest(BaseModel):
    message: str
    sender: Optional[str] = None


@router.post("/analyze")
async def analyze_sms(
    request: SmsAnalyzeRequest,
    db: Session = Depends(get_db_dependency),
    current_user: Optional[dict] = Depends(get_optional_user),
):
    """Analyse an SMS message for scam/phishing indicators."""
    if not request.message or not request.message.strip():
        raise HTTPException(
            status_code=422,
            detail={"error": {"code": "EMPTY_MESSAGE", "message": "SMS message cannot be empty."}},
        )
    if len(request.message) > 10000:
        raise HTTPException(
            status_code=422,
            detail={"error": {"code": "TOO_LONG", "message": "Message exceeds 10,000 characters."}},
        )

    t_start = time.perf_counter()
    try:
        result, sms_details = await _service.analyse(request.message, request.sender)
    except Exception as e:
        logger.error(f"SMS analysis error: {e}")
        raise HTTPException(
            status_code=500,
            detail={"error": {"code": "ANALYSIS_ERROR", "message": "SMS analysis failed."}},
        )

    duration_ms = int((time.perf_counter() - t_start) * 1000)
    input_hash = hashlib.sha256(request.message.encode()).hexdigest()
    user_id = current_user["id"] if current_user else None

    inv_id = save_investigation(db, result, sms_details, duration_ms, input_hash, user_id=user_id)
    result.saved = inv_id is not None

    return result.model_dump()
