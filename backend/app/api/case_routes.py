"""FastAPI routes for Case and Evidence Ledger management."""
from __future__ import annotations

import io
import json
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.cases.service import add_note, get_case, list_cases, verify_case
from app.database.connection import get_db_dependency

router = APIRouter(prefix="/cases", tags=["cases"])


class NoteRequest(BaseModel):
    text: str


@router.get("")
def get_user_cases(
    db: Session = Depends(get_db_dependency),
    current_user: dict = Depends(get_current_user),
):
    """Retrieve all open cases for the current authenticated user."""
    return list_cases(db, current_user["id"])


@router.get("/{case_id}")
def get_case_by_id(
    case_id: str,
    db: Session = Depends(get_db_dependency),
    current_user: dict = Depends(get_current_user),
):
    """Retrieve full details, graph nodes/edges, clues, and ledger of a case."""
    case_data = get_case(db, case_id, current_user["id"])
    if not case_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "NOT_FOUND", "message": "Case not found or access denied."}},
        )
    return case_data


@router.get("/{case_id}/verify")
def verify_case_integrity(
    case_id: str,
    db: Session = Depends(get_db_dependency),
    current_user: dict = Depends(get_current_user),
):
    """Verify cryptographic hash chain, head signature, and evidence content."""
    res = verify_case(db, case_id, current_user["id"])
    if res.get("status") == "tampered" and "Case not found" in str(res.get("problems", [])):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "NOT_FOUND", "message": "Case not found or access denied."}},
        )
    return res


@router.post("/{case_id}/notes")
def post_case_note(
    case_id: str,
    req: NoteRequest,
    db: Session = Depends(get_db_dependency),
    current_user: dict = Depends(get_current_user),
):
    """Add an investigator note to the case ledger."""
    if not req.text or not req.text.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": {"code": "EMPTY_NOTE", "message": "Note text cannot be empty."}},
        )
    try:
        ev = add_note(db, case_id, current_user["id"], req.text.strip())
        return {"success": True, "event": ev}
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "NOT_FOUND", "message": str(e)}},
        )


@router.get("/{case_id}/export.json")
def export_case_json(
    case_id: str,
    db: Session = Depends(get_db_dependency),
    current_user: dict = Depends(get_current_user),
):
    """Export case data and verification record as JSON."""
    case_data = get_case(db, case_id, current_user["id"])
    if not case_data:
        raise HTTPException(status_code=404, detail="Case not found.")
    verification = verify_case(db, case_id, current_user["id"])
    export_payload = {
        "disclaimer": "This document is a technical integrity record to assist in preparing a certificate under Section 63 of the Bharatiya Sakshya Adhiniyam, 2023 (BSA 2023) and is NOT itself a legal certificate.",
        "case": case_data,
        "verification": verification,
    }
    content = json.dumps(export_payload, indent=2)
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=case_{case_id[:8]}_export.json"},
    )


@router.get("/{case_id}/export.pdf")
def export_case_pdf(
    case_id: str,
    db: Session = Depends(get_db_dependency),
    current_user: dict = Depends(get_current_user),
):
    """Export tamper-evident case report as PDF with Section 63 BSA 2023 notice."""
    case_data = get_case(db, case_id, current_user["id"])
    if not case_data:
        raise HTTPException(status_code=404, detail="Case not found.")
    verification = verify_case(db, case_id, current_user["id"])

    pdf_stream = _build_case_pdf(case_data, verification)
    return StreamingResponse(
        pdf_stream,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=case_{case_id[:8]}_integrity_report.pdf"},
    )


def _build_case_pdf(case_data: Dict[str, Any], verification: Dict[str, Any]) -> io.BytesIO:
    """Generate professional tamper-evident integrity PDF using ReportLab."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.platypus import HRFlowable, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
    )
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0f172a"),
    )
    h2_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=10,
        spaceAfter=4,
    )
    body_style = ParagraphStyle(
        "BodyDark",
        parent=styles["Normal"],
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#334155"),
    )
    disclaimer_style = ParagraphStyle(
        "Disclaimer",
        parent=styles["Normal"],
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#b45309"),
        backColor=colors.HexColor("#fef3c7"),
        borderColor=colors.HexColor("#f59e0b"),
        borderWidth=1,
        borderPadding=6,
        spaceBefore=8,
        spaceAfter=8,
    )

    story = []

    # Title & Header
    story.append(Paragraph("PhishShield — Case Integrity & Ledger Audit Record", title_style))
    story.append(Spacer(1, 6))

    # Mandatory Legal Notice (Section 63 BSA 2023)
    notice_text = (
        "<b>LEGAL NOTICE & STATUTORY CONTEXT:</b><br/>"
        "This document is a technical integrity record generated by PhishShield to help prepare a certificate "
        "under <b>Section 63 of the Bharatiya Sakshya Adhiniyam, 2023 (BSA 2023)</b> regarding electronic records "
        "and is <b>NOT</b> itself a legal certificate. This record documents the cryptographic chain of custody, "
        "SHA-256 evidence fingerprints, and chronological tamper-evident ledger events."
    )
    story.append(Paragraph(notice_text, disclaimer_style))
    story.append(Spacer(1, 6))

    # Case Summary Table
    cid = case_data.get("id", "")
    risk = case_data.get("risk_level", "").upper()
    v_status = verification.get("status", "unknown").upper()
    head_hash = case_data.get("head_hash", "")
    sig = case_data.get("signature", "")

    summary_data = [
        [Paragraph("<b>Case ID:</b>", body_style), Paragraph(cid, body_style)],
        [Paragraph("<b>Title:</b>", body_style), Paragraph(case_data.get("title", ""), body_style)],
        [Paragraph("<b>Risk Level:</b>", body_style), Paragraph(risk, body_style)],
        [Paragraph("<b>Integrity Status:</b>", body_style), Paragraph(f"<b>{v_status}</b>", body_style)],
        [Paragraph("<b>Ledger Head SHA-256:</b>", body_style), Paragraph(f"<font name='Courier'>{head_hash}</font>", body_style)],
        [Paragraph("<b>HMAC Signature:</b>", body_style), Paragraph(f"<font name='Courier'>{sig[:32]}...</font>", body_style)],
        [Paragraph("<b>Created At:</b>", body_style), Paragraph(case_data.get("created_at", ""), body_style)],
        [Paragraph("<b>Updated At:</b>", body_style), Paragraph(case_data.get("updated_at", ""), body_style)],
    ]
    t_summary = Table(summary_data, colWidths=[120, 420])
    t_summary.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(t_summary)
    story.append(Spacer(1, 10))

    # Members / Evidence Items
    story.append(Paragraph("1. Attached Evidence Items", h2_style))
    members = case_data.get("members", [])
    if members:
        mem_rows = [["Module", "Verdict", "Input / Summary", "Result SHA-256"]]
        for m in members:
            mem_rows.append([
                Paragraph(m.get("type", "").upper(), body_style),
                Paragraph(m.get("verdict", "").upper(), body_style),
                Paragraph((m.get("input_display") or m.get("summary") or "")[:45], body_style),
                Paragraph(f"<font name='Courier'>{m.get('result_hash', '')[:16]}...</font>", body_style),
            ])
        t_mem = Table(mem_rows, colWidths=[65, 75, 240, 160])
        t_mem.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#f1f5f9")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        story.append(t_mem)
    else:
        story.append(Paragraph("No evidence items attached.", body_style))
    story.append(Spacer(1, 10))

    # Shared Clues / Entities
    story.append(Paragraph("2. Shared Clues & Correlated Entities", h2_style))
    clues = case_data.get("clues", [])
    if clues:
        clue_rows = [["Type", "Entity Value", "Shared In", "Linkable"]]
        for c in clues[:15]:
            is_sh = "YES (Shared)" if c.get("is_shared") else "Single"
            clue_rows.append([
                Paragraph(c.get("entity_type", "").upper(), body_style),
                Paragraph(c.get("entity_value", "")[:45], body_style),
                Paragraph(f"{c.get('count', 1)} item(s) - {is_sh}", body_style),
                Paragraph("True", body_style),
            ])
        t_clues = Table(clue_rows, colWidths=[80, 260, 120, 80])
        t_clues.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#f1f5f9")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        story.append(t_clues)
    else:
        story.append(Paragraph("No correlated clues found.", body_style))
    story.append(Spacer(1, 10))

    # Ledger Events Table
    story.append(Paragraph("3. Cryptographic Ledger Events (Tamper-Evident Hash Chain)", h2_style))
    events = case_data.get("events", [])
    if events:
        ev_rows = [["#", "Timestamp", "Event Type", "Prev Hash", "Record Hash"]]
        for ev in events:
            ev_rows.append([
                Paragraph(str(ev.get("seq")), body_style),
                Paragraph(ev.get("ts", "")[:19], body_style),
                Paragraph(ev.get("event_type", ""), body_style),
                Paragraph(f"<font name='Courier'>{ev.get('prev_hash', '')[:8]}...</font>", body_style),
                Paragraph(f"<font name='Courier'>{ev.get('record_hash', '')[:8]}...</font>", body_style),
            ])
        t_ev = Table(ev_rows, colWidths=[25, 120, 105, 145, 145])
        t_ev.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#f1f5f9")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        story.append(t_ev)
    story.append(Spacer(1, 10))

    # Verification Result Details
    story.append(Paragraph("4. Technical Integrity Verification Results", h2_style))
    v_rows = [
        [Paragraph("<b>Hash Chain Linkage:</b>", body_style), Paragraph("VALID" if verification.get("chain_valid") else "FAILED", body_style)],
        [Paragraph("<b>Signature Match:</b>", body_style), Paragraph("VALID" if verification.get("signature_valid") else "FAILED", body_style)],
    ]
    for mb in verification.get("members", []):
        v_rows.append([
            Paragraph(f"<b>Evidence {mb['investigation_id'][:8]}:</b>", body_style),
            Paragraph(mb.get("status", "").upper(), body_style),
        ])
    if verification.get("problems"):
        for p in verification["problems"]:
            v_rows.append([Paragraph("<font color='red'><b>Integrity Issue:</b></font>", body_style), Paragraph(f"<font color='red'>{p}</font>", body_style)])

    t_v = Table(v_rows, colWidths=[160, 380])
    t_v.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    story.append(t_v)

    doc.build(story)
    buf.seek(0)
    return buf
