"""History, reports, and dashboard API routes."""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.database.connection import get_db_dependency
from app.database.repository import (
    delete_investigation,
    get_dashboard_stats,
    get_history,
    get_investigation_by_id,
)

router = APIRouter(tags=["history"])
logger = logging.getLogger(__name__)


@router.get("/history")
async def list_history(
    type: Optional[str] = Query(None),
    verdict: Optional[str] = Query(None),
    q: Optional[str] = Query(None),
    from_date: Optional[str] = Query(None, alias="from"),
    to_date: Optional[str] = Query(None, alias="to"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    sort: str = Query("desc"),
    db: Session = Depends(get_db_dependency),
    current_user: dict = Depends(get_current_user),
):
    """List investigations with filtering, search, and pagination."""
    from_dt = None
    to_dt = None
    if from_date:
        try:
            from_dt = datetime.fromisoformat(from_date)
        except ValueError:
            raise HTTPException(400, detail={"error": {"code": "INVALID_DATE", "message": "Invalid 'from' date."}})
    if to_date:
        try:
            to_dt = datetime.fromisoformat(to_date)
        except ValueError:
            raise HTTPException(400, detail={"error": {"code": "INVALID_DATE", "message": "Invalid 'to' date."}})

    items, total = get_history(
        db, type, verdict, q, from_dt, to_dt, page, page_size, sort,
        user_id=current_user["id"],
    )
    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "has_more": (page * page_size) < total,
    }


@router.get("/history/{investigation_id}")
async def get_report(
    investigation_id: str,
    db: Session = Depends(get_db_dependency),
    current_user: dict = Depends(get_current_user),
):
    """Get full investigation report by ID."""
    record = get_investigation_by_id(db, investigation_id, user_id=current_user["id"])
    if not record:
        raise HTTPException(
            status_code=404,
            detail={"error": {"code": "NOT_FOUND", "message": "Investigation not found."}},
        )
    return record


@router.delete("/history/{investigation_id}")
async def delete_report(
    investigation_id: str,
    db: Session = Depends(get_db_dependency),
    current_user: dict = Depends(get_current_user),
):
    """Delete an investigation record."""
    deleted = delete_investigation(db, investigation_id, user_id=current_user["id"])
    if not deleted:
        raise HTTPException(
            status_code=404,
            detail={"error": {"code": "NOT_FOUND", "message": "Investigation not found."}},
        )
    return {"success": True, "message": "Investigation deleted."}


@router.get("/history/{investigation_id}/export.pdf")
async def export_pdf(
    investigation_id: str,
    db: Session = Depends(get_db_dependency),
    current_user: dict = Depends(get_current_user),
):
    """Export investigation as PDF."""
    record = get_investigation_by_id(db, investigation_id, user_id=current_user["id"])
    if not record:
        raise HTTPException(
            status_code=404,
            detail={"error": {"code": "NOT_FOUND", "message": "Investigation not found."}},
        )

    try:
        pdf_bytes = _generate_pdf(record)
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail={"error": {"code": "PDF_UNAVAILABLE", "message": "PDF generation requires reportlab. pip install reportlab"}},
        )
    except Exception as e:
        logger.error(f"PDF generation failed: {e}")
        raise HTTPException(
            status_code=500,
            detail={"error": {"code": "PDF_ERROR", "message": "PDF generation failed."}},
        )

    filename = f"phishshield_{investigation_id[:8]}.pdf"
    return StreamingResponse(
        iter([pdf_bytes]),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/dashboard/stats")
async def dashboard_stats(
    db: Session = Depends(get_db_dependency),
    current_user: dict = Depends(get_current_user),
):
    """Return real dashboard statistics from the database (user-scoped)."""
    stats = get_dashboard_stats(db, user_id=current_user["id"])
    return stats


def _generate_pdf(record: dict) -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    from reportlab.lib import colors
    import io

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, rightMargin=50, leftMargin=50, topMargin=50, bottomMargin=50)
    styles = getSampleStyleSheet()
    story = []

    # Title
    story.append(Paragraph("PhishShield Investigation Report", styles["Title"]))
    story.append(Spacer(1, 12))

    # Disclaimer
    disclaimer = (
        "DISCLAIMER: This report was generated by automated analysis tools. "
        "Results are indicators only and do not constitute legal or forensic proof. "
        "Always verify through official channels. This is not a police or court document."
    )
    story.append(Paragraph(disclaimer, styles["Italic"]))
    story.append(Spacer(1, 12))

    # Summary table
    data = [
        ["Investigation ID", record["id"]],
        ["Type", record["type"].upper()],
        ["Date", record["created_at"]],
        ["Verdict", record["display_label"]],
        ["Status", record["status"]],
    ]
    t = Table(data, colWidths=[150, 320])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EFF6FF")),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t)
    story.append(Spacer(1, 12))

    # Summary
    story.append(Paragraph("Summary", styles["Heading2"]))
    story.append(Paragraph(record.get("summary", ""), styles["BodyText"]))
    story.append(Spacer(1, 12))

    # Evidence
    result_json = record.get("result_json") or {}
    evidence = result_json.get("evidence", [])
    if evidence:
        story.append(Paragraph("Evidence & Findings", styles["Heading2"]))
        for ev in evidence:
            story.append(Paragraph(
                f"[{ev.get('severity', '').upper()}] {ev.get('title', '')}",
                styles["Heading3"]
            ))
            story.append(Paragraph(ev.get("detail", ""), styles["BodyText"]))
        story.append(Spacer(1, 12))

    # Recommendations
    recs = result_json.get("recommendations", [])
    if recs:
        story.append(Paragraph("Recommended Actions", styles["Heading2"]))
        for r in recs:
            story.append(Paragraph(f"• {r}", styles["BodyText"]))
        story.append(Spacer(1, 12))

    # Limitations
    lims = result_json.get("limitations", [])
    if lims:
        story.append(Paragraph("Analysis Limitations", styles["Heading2"]))
        for l in lims:
            story.append(Paragraph(f"• {l}", styles["BodyText"]))

    doc.build(story)
    return buf.getvalue()
