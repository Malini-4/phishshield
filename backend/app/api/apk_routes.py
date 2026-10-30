"""APK analysis API routes."""
from __future__ import annotations

import hashlib
import logging
import time
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.auth.dependencies import get_optional_user
from app.config import get_settings
from app.database.connection import get_db_dependency
from app.database.repository import save_investigation
from app.services.apk_service import ApkAnalysisService

router = APIRouter(tags=["apk"])
logger = logging.getLogger(__name__)
_service = ApkAnalysisService()


@router.post("/analyze")
async def analyze_apk(
    file: UploadFile = File(...),
    db: Session = Depends(get_db_dependency),
    current_user: Optional[dict] = Depends(get_optional_user),
):
    """Analyse an Android APK file (static analysis only – never executed)."""
    settings = get_settings()
    max_bytes = settings.max_apk_bytes

    # Check content type loosely (also validated by magic bytes in service)
    allowed_content_types = {
        "application/vnd.android.package-archive",
        "application/zip",
        "application/octet-stream",
        "application/x-zip-compressed",
    }
    if file.content_type and file.content_type not in allowed_content_types:
        logger.info(f"APK upload rejected: content_type={file.content_type}")

    # Stream with size limit
    chunks = []
    total = 0
    while True:
        chunk = await file.read(65536)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise HTTPException(
                status_code=413,
                detail={"error": {"code": "FILE_TOO_LARGE",
                                   "message": f"APK exceeds {settings.MAX_APK_MB} MB limit."}},
            )
        chunks.append(chunk)

    data = b"".join(chunks)
    if not data:
        raise HTTPException(
            status_code=422,
            detail={"error": {"code": "EMPTY_FILE", "message": "Uploaded file is empty."}},
        )

    t_start = time.perf_counter()
    try:
        result, apk_details = await _service.analyse(data, file.filename or "upload.apk")
    except Exception as e:
        logger.error(f"APK analysis error: {e}")
        raise HTTPException(
            status_code=500,
            detail={"error": {"code": "ANALYSIS_ERROR", "message": "APK analysis failed."}},
        )

    duration_ms = int((time.perf_counter() - t_start) * 1000)
    input_hash = hashlib.sha256(data).hexdigest()
    user_id = current_user["id"] if current_user else None

    inv_id = save_investigation(db, result, apk_details, duration_ms, input_hash, user_id=user_id)
    result.saved = inv_id is not None

    case_id = None
    if current_user and inv_id:
        try:
            db.commit()
            from app.cases.service import process_investigation
            case_id = process_investigation(
                db, inv_id, current_user["id"], result.model_dump(), apk_details
            )
            if case_id:
                result.case_id = case_id
        except Exception as e:
            logger.warning(f"Failed to process case for APK investigation {inv_id}: {e}")

    resp = result.model_dump()
    if case_id:
        resp["case_id"] = case_id
    return resp

