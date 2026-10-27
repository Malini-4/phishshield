"""
History and report repository layer.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import func, select, desc, and_, or_
from sqlalchemy.orm import Session

from app.database.models import (
    Investigation, EvidenceItem as DBEvidence, CheckRecord,
    UrlDetails, ApkDetails, SmsDetails, ScreenshotDetails,
)
from app.schemas.shared import AnalysisResult, Verdict

logger = logging.getLogger(__name__)


def save_investigation(
    db: Session,
    result: AnalysisResult,
    module_details: Optional[dict],
    duration_ms: int = 0,
    input_hash: str = "",
    user_id: Optional[str] = None,
) -> Optional[str]:
    """
    Save a completed investigation to the database.
    Returns investigation_id on success, None on failure.
    """
    try:
        inv = Investigation(
            id=result.investigation_id,
            user_id=user_id,
            type=result.type.value,
            created_at=datetime.fromisoformat(result.created_at).replace(tzinfo=timezone.utc),
            verdict=result.verdict.value,
            display_label=result.display_label,
            summary=result.summary,
            input_display=result.input_summary[:500],
            input_hash=input_hash,
            analysis_version=result.analysis_version,
            model_version=result.model_version,
            status="completed",
            duration_ms=duration_ms,
            result_json=result.model_dump(),
        )
        db.add(inv)

        # Evidence items
        for ev in result.evidence:
            db.add(DBEvidence(
                investigation_id=result.investigation_id,
                category=ev.category,
                severity=ev.severity.value,
                title=ev.title,
                detail=ev.detail,
                source=ev.source.value,
            ))

        # Checks
        for check in result.checks_performed:
            db.add(CheckRecord(
                investigation_id=result.investigation_id,
                name=check.name,
                status=check.status.value,
                detail=check.detail,
            ))

        # Module-specific details
        if module_details and result.type.value == "url":
            db.add(UrlDetails(
                investigation_id=result.investigation_id,
                original_url=module_details.get("original_url", ""),
                registrable_domain=module_details.get("registrable_domain"),
                scheme=module_details.get("scheme"),
                host=module_details.get("host"),
                path=module_details.get("path"),
                model_score=module_details.get("model_score"),
                model_band=module_details.get("model_band"),
                reputation_results=module_details.get("reputation_results"),
                rule_hits=module_details.get("rule_hits"),
                features_summary=module_details.get("features_summary"),
            ))

        elif module_details and result.type.value == "apk":
            db.add(ApkDetails(
                investigation_id=result.investigation_id,
                package_name=module_details.get("package_name"),
                app_label=module_details.get("app_label"),
                version_name=module_details.get("version_name"),
                version_code=module_details.get("version_code"),
                sha256=module_details.get("sha256"),
                md5=module_details.get("md5"),
                file_size_bytes=module_details.get("file_size_bytes"),
                permissions=module_details.get("permissions"),
                sensitive_permissions=module_details.get("sensitive_permissions"),
                embedded_urls=module_details.get("embedded_urls"),
                min_sdk=module_details.get("min_sdk"),
                target_sdk=module_details.get("target_sdk"),
            ))

        elif module_details and result.type.value == "sms":
            db.add(SmsDetails(
                investigation_id=result.investigation_id,
                sender=module_details.get("sender"),
                sender_state=module_details.get("sender_state"),
                message_hash=module_details.get("message_hash"),
                redacted_text=module_details.get("redacted_text"),
                extracted_urls=module_details.get("extracted_urls"),
                message_length=module_details.get("message_length"),
            ))

        elif module_details and result.type.value == "screenshot":
            db.add(ScreenshotDetails(
                investigation_id=result.investigation_id,
                file_hash=module_details.get("file_hash"),
                file_size_bytes=module_details.get("file_size_bytes"),
                image_width=module_details.get("image_width"),
                image_height=module_details.get("image_height"),
                ocr_engine=module_details.get("ocr_engine"),
                ocr_confidence=module_details.get("ocr_confidence"),
                extracted_fields=module_details.get("extracted_fields"),
            ))

        db.flush()
        logger.info(f"Saved investigation {result.investigation_id} ({result.type.value}, {result.verdict.value})")
        return result.investigation_id

    except Exception as e:
        logger.error(f"Failed to save investigation: {e}")
        db.rollback()
        return None


def get_history(
    db: Session,
    type_filter: Optional[str] = None,
    verdict_filter: Optional[str] = None,
    search: Optional[str] = None,
    from_date: Optional[datetime] = None,
    to_date: Optional[datetime] = None,
    page: int = 1,
    page_size: int = 20,
    sort: str = "desc",
    user_id: Optional[str] = None,
) -> tuple[list[dict], int]:
    """Return paginated history with total count. When user_id is provided,
    results are scoped to that user's investigations only."""
    query = select(Investigation)

    filters = []
    if user_id is not None:
        filters.append(Investigation.user_id == user_id)
    if type_filter:
        filters.append(Investigation.type == type_filter)
    if verdict_filter:
        filters.append(Investigation.verdict == verdict_filter)
    if search:
        filters.append(Investigation.input_display.ilike(f"%{search}%"))
    if from_date:
        filters.append(Investigation.created_at >= from_date)
    if to_date:
        filters.append(Investigation.created_at <= to_date)

    if filters:
        query = query.where(and_(*filters))

    # Count
    count_q = select(func.count()).select_from(query.subquery())
    total = db.execute(count_q).scalar() or 0

    # Sort and paginate
    if sort == "asc":
        query = query.order_by(Investigation.created_at.asc())
    else:
        query = query.order_by(Investigation.created_at.desc())

    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)

    rows = db.execute(query).scalars().all()
    items = []
    for row in rows:
        items.append({
            "id": row.id,
            "type": row.type,
            "created_at": row.created_at.isoformat(),
            "verdict": row.verdict,
            "display_label": row.display_label,
            "summary": row.summary,
            "input_display": row.input_display,
            "status": row.status,
            "duration_ms": row.duration_ms,
        })
    return items, total


def get_investigation_by_id(
    db: Session, investigation_id: str, user_id: Optional[str] = None
) -> Optional[dict]:
    """Return full investigation record including result_json.
    If user_id is provided, returns None if the record does not belong to that user."""
    inv = db.execute(
        select(Investigation).where(Investigation.id == investigation_id)
    ).scalar_one_or_none()
    if not inv:
        return None
    # Ownership check: if user_id is specified, verify it matches
    # Legacy records with user_id=None are accessible to any authenticated user
    if user_id is not None and inv.user_id is not None and inv.user_id != user_id:
        return None
    return {
        "id": inv.id,
        "type": inv.type,
        "created_at": inv.created_at.isoformat(),
        "verdict": inv.verdict,
        "display_label": inv.display_label,
        "summary": inv.summary,
        "input_display": inv.input_display,
        "status": inv.status,
        "duration_ms": inv.duration_ms,
        "model_version": inv.model_version,
        "analysis_version": inv.analysis_version,
        "result_json": inv.result_json,
    }


def delete_investigation(
    db: Session, investigation_id: str, user_id: Optional[str] = None
) -> bool:
    """Delete an investigation and all related records. Returns True if deleted.
    If user_id is provided, only deletes if the investigation belongs to that user."""
    inv = db.execute(
        select(Investigation).where(Investigation.id == investigation_id)
    ).scalar_one_or_none()
    if not inv:
        return False
    # Ownership check
    if user_id is not None and inv.user_id is not None and inv.user_id != user_id:
        return False
    db.delete(inv)
    db.flush()
    return True


def get_dashboard_stats(db: Session, user_id: Optional[str] = None) -> dict:
    """Return real stats from the database. When user_id is provided,
    stats are scoped to that user's investigations."""
    from datetime import timedelta

    # Build base filter
    user_filter = (Investigation.user_id == user_id) if user_id is not None else None

    def apply_filter(q):
        if user_filter is not None:
            return q.where(user_filter)
        return q

    total = db.execute(apply_filter(select(func.count(Investigation.id)))).scalar() or 0

    # By type
    type_counts = {}
    for row in db.execute(
        apply_filter(
            select(Investigation.type, func.count(Investigation.id))
            .group_by(Investigation.type)
        )
    ).all():
        type_counts[row[0]] = row[1]

    # By verdict
    verdict_counts = {}
    for row in db.execute(
        apply_filter(
            select(Investigation.verdict, func.count(Investigation.id))
            .group_by(Investigation.verdict)
        )
    ).all():
        verdict_counts[row[0]] = row[1]

    # Recent 5
    recent = db.execute(
        apply_filter(
            select(Investigation).order_by(Investigation.created_at.desc()).limit(5)
        )
    ).scalars().all()

    recent_items = [{
        "id": r.id,
        "type": r.type,
        "created_at": r.created_at.isoformat(),
        "verdict": r.verdict,
        "display_label": r.display_label,
        "input_display": r.input_display,
    } for r in recent]

    # Last 30-day trend
    cutoff_30 = datetime.now(timezone.utc) - timedelta(days=30)
    cutoff_7 = datetime.now(timezone.utc) - timedelta(days=7)

    base_30 = select(func.count(Investigation.id)).where(Investigation.created_at >= cutoff_30)
    base_7 = select(func.count(Investigation.id)).where(Investigation.created_at >= cutoff_7)
    if user_filter is not None:
        base_30 = base_30.where(user_filter)
        base_7 = base_7.where(user_filter)

    count_30d = db.execute(base_30).scalar() or 0
    count_7d = db.execute(base_7).scalar() or 0

    return {
        "total": total,
        "by_type": type_counts,
        "by_verdict": verdict_counts,
        "last_7d": count_7d,
        "last_30d": count_30d,
        "recent": recent_items,
    }

