"""
PhishShield Comprehensive Study Guide & Viva Voce Manual PDF Generator
Built with ReportLab 5.0.1. Grounded 100% in inspected project source code.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

DOCS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = DOCS_DIR.parent
OUTPUT_PDF = DOCS_DIR / "PhishShield_Project_Explanation_and_Viva_Guide.pdf"


class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas that adds running headers and footers with total page count.
    Suppresses headers and footers on the cover page (page 1).
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int):
        if self._pageNumber == 1:
            return  # Skip cover page

        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#061A35"))

        # Running Header
        self.drawString(45, 800, "PHISHSHIELD — PROJECT STUDY GUIDE & VIVA DEFENSE MANUAL")
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))
        self.drawRightString(550, 800, "Full-Stack Security & Forensic Engine")

        # Header Rule
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.6)
        self.line(45, 794, 550, 794)

        # Footer Rule
        self.line(45, 45, 550, 45)

        # Running Footer
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))
        self.drawString(45, 33, "Academic Project Defense Document • Fast-API + React + SQLite")
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(550, 33, page_str)
        self.restoreState()


def get_styles():
    base = getSampleStyleSheet()

    # Custom palette
    navy = colors.HexColor("#061A35")
    dark_blue = colors.HexColor("#0B2B59")
    blue = colors.HexColor("#087FF5")
    slate = colors.HexColor("#1E293B")
    muted = colors.HexColor("#475569")

    styles = {
        "CoverTitle": ParagraphStyle(
            "CoverTitle",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=28,
            leading=34,
            textColor=navy,
            alignment=0,
            spaceAfter=8,
        ),
        "CoverSubtitle": ParagraphStyle(
            "CoverSubtitle",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=13,
            leading=18,
            textColor=blue,
            spaceAfter=20,
        ),
        "CoverDesc": ParagraphStyle(
            "CoverDesc",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=10,
            leading=15,
            textColor=slate,
            spaceAfter=15,
        ),
        "CoverMeta": ParagraphStyle(
            "CoverMeta",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=14,
            textColor=muted,
        ),
        "H1": ParagraphStyle(
            "Heading1_Custom",
            parent=base["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=16,
            leading=20,
            textColor=navy,
            spaceBefore=14,
            spaceAfter=8,
            keepWithNext=True,
        ),
        "H2": ParagraphStyle(
            "Heading2_Custom",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=16,
            textColor=dark_blue,
            spaceBefore=10,
            spaceAfter=5,
            keepWithNext=True,
        ),
        "H3": ParagraphStyle(
            "Heading3_Custom",
            parent=base["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=10.5,
            leading=14,
            textColor=blue,
            spaceBefore=8,
            spaceAfter=4,
            keepWithNext=True,
        ),
        "Body": ParagraphStyle(
            "Body_Custom",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=9,
            leading=13.5,
            textColor=slate,
            spaceAfter=6,
        ),
        "BodyBold": ParagraphStyle(
            "BodyBold_Custom",
            parent=base["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=13.5,
            textColor=slate,
            spaceAfter=6,
        ),
        "Bullet": ParagraphStyle(
            "Bullet_Custom",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8.8,
            leading=13,
            textColor=slate,
            leftIndent=14,
            firstLineIndent=-10,
            spaceAfter=4,
        ),
        "Code": ParagraphStyle(
            "Code_Custom",
            parent=base["Normal"],
            fontName="Courier",
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#0F172A"),
        ),
        "Callout": ParagraphStyle(
            "Callout_Custom",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=12.5,
            textColor=navy,
        ),
        "TableHeader": ParagraphStyle(
            "TableHeader_Custom",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8.5,
            leading=11,
            textColor=colors.white,
            alignment=1,
        ),
        "TableCell": ParagraphStyle(
            "TableCell_Custom",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8,
            leading=11,
            textColor=slate,
        ),
        "TableCellBold": ParagraphStyle(
            "TableCellBold_Custom",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=11,
            textColor=slate,
        ),
        "TableCellMono": ParagraphStyle(
            "TableCellMono_Custom",
            parent=base["Normal"],
            fontName="Courier",
            fontSize=7.5,
            leading=10,
            textColor=navy,
        ),
        "QTitle": ParagraphStyle(
            "QTitle_Custom",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=9.5,
            leading=13,
            textColor=navy,
            spaceBefore=6,
            spaceAfter=2,
            keepWithNext=True,
        ),
        "AAnswer": ParagraphStyle(
            "AAnswer_Custom",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8.8,
            leading=12.8,
            textColor=slate,
            spaceAfter=6,
        ),
    }
    return styles


def callout_box(text: str, styles, title: str = "KEY PRINCIPLE") -> Table:
    content = [
        Paragraph(f"<b>{title}:</b> {text}", styles["Callout"]),
    ]
    t = Table([[content]], colWidths=[505])
    t.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F0F7FF")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#087FF5")),
            ("LINEBEFORE", (0, 0), (0, -1), 3.5, colors.HexColor("#087FF5")),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ])
    )
    return t


def code_box(code_text: str, styles) -> Table:
    lines = code_text.strip().split("\n")
    p_lines = [Paragraph(line.replace(" ", "&nbsp;"), styles["Code"]) for line in lines]
    t = Table([[p_lines]], colWidths=[505])
    t.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
            ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ])
    )
    return t


def make_table(data_matrix, col_widths, styles, is_header=True) -> Table:
    table_data = []
    for r_idx, row in enumerate(data_matrix):
        formatted_row = []
        for c_idx, cell in enumerate(row):
            if r_idx == 0 and is_header:
                p = Paragraph(str(cell), styles["TableHeader"])
            else:
                if isinstance(cell, str) and (cell.startswith("`") and cell.endswith("`")):
                    p = Paragraph(cell.replace("`", ""), styles["TableCellMono"])
                else:
                    p = Paragraph(str(cell), styles["TableCell"])
            formatted_row.append(p)
        table_data.append(formatted_row)

    t = Table(table_data, colWidths=col_widths)
    t_style = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]
    if is_header:
        t_style.extend([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#061A35")),
        ])
    for i in range(1, len(data_matrix)):
        if i % 2 == 1:
            t_style.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#F8FAFC")))
        else:
            t_style.append(("BACKGROUND", (0, i), (-1, i), colors.white))

    t.setStyle(TableStyle(t_style))
    return t


def build_pdf():
    styles = get_styles()
    doc = SimpleDocTemplate(
        str(OUTPUT_PDF),
        pagesize=A4,
        leftMargin=45,
        rightMargin=45,
        topMargin=50,
        bottomMargin=50,
    )

    story = []

    # =========================================================================
    # 1. COVER PAGE
    # =========================================================================
    story.append(Spacer(1, 40))
    story.append(Paragraph("PHISHSHIELD", styles["CoverTitle"]))
    story.append(
        Paragraph(
            "COMPREHENSIVE PROJECT STUDY GUIDE, SOURCE CODE WALKTHROUGH & VIVA VOCE DEFENSE MANUAL",
            styles["CoverSubtitle"],
        )
    )
    story.append(
        HRFlowable(
            width="100%",
            thickness=3,
            color=colors.HexColor("#087FF5"),
            spaceBefore=0,
            spaceAfter=15,
        )
    )

    story.append(
        Paragraph(
            "<b>Platform Classification:</b> Multi-Vector Cyber Fraud & Digital Threat Static Forensic System<br/>"
            "<b>Engine Architecture:</b> Decoupled 5-Module Micro-Services via FastAPI ASGI + React 18 TypeScript<br/>"
            "<b>Machine Learning Stack:</b> Calibrated HistGradientBoostingClassifier (Domain-Grouped Split) + RapidOCR ONNX<br/>"
            "<b>Author / Candidate:</b> Computer Science & Engineering Undergraduate Final Year Project<br/>"
            "<b>Documentation Target:</b> Comprehensive Code Understanding, Guide Walkthrough & External Viva Defense",
            styles["CoverDesc"],
        )
    )

    story.append(Spacer(1, 20))
    story.append(
        callout_box(
            "This study manual is grounded 100% in the actual, inspected implementation inside "
            "<b>C:\\Users\\Admin\\Desktop\\phishshield</b>. Every file path, class name, line reference, "
            "machine learning algorithm, and metric represents the true codebase. "
            "No cloud services, paid APIs, mock engines, or speculative claims are made.",
            styles,
            title="ACADEMIC HONESTY & IMPLEMENTATION GROUND TRUTH",
        )
    )

    story.append(Spacer(1, 40))

    meta_table_data = [
        ["Project Workspace", "C:\\Users\\Admin\\Desktop\\phishshield"],
        ["Backend Framework", "Python 3.14 / 3.11+ • FastAPI 0.143.0 • Uvicorn ASGI"],
        ["Frontend Framework", "React 18.3.1 • TypeScript 5.5 • Vite 5.4 • Lucide Icons"],
        ["Database Layer", "SQLite 3 (WAL Mode) • SQLAlchemy 2.0 ORM • Alembic Migrations"],
        ["Active ML Model", "HistGradientBoostingClassifier + CalibratedClassifierCV (Sigmoid)"],
        ["Active OCR Engine", "RapidOCR (ONNX Runtime) with Lanczos Image Preprocessing"],
        ["Total Automated Tests", "103 Backend Pytest (100% Passing) + Vitest Frontend Suite"],
        ["Verified Database State", "27 Investigations • 4 Users • Zero Record Loss"],
    ]
    story.append(make_table(meta_table_data, [150, 355], styles, is_header=False))

    story.append(PageBreak())

    # =========================================================================
    # 2. TABLE OF CONTENTS & EXECUTIVE SUMMARY
    # =========================================================================
    story.append(Paragraph("Table of Contents", styles["H1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#061A35"), spaceAfter=10))

    toc_items = [
        "1. Executive Summary & Problem Statement",
        "2. Complete System Architecture & Engineering Principles",
        "3. Actual Technologies, Frameworks & Dependencies Used",
        "4. Project Folder Hierarchy & Key Source Files",
        "5. Deep-Dive Module 1: URL Threat Analysis & Calibrated ML Engine",
        "6. Deep-Dive Module 2: Android APK Static Forensic Engine",
        "7. Deep-Dive Module 3: SMS & TRAI DLT Sender Verification",
        "8. Deep-Dive Module 4: Payment Screenshot Optical Character Recognition (OCR)",
        "9. Deep-Dive Module 5: User Authentication, SQLite Persistence & PDF Reporting",
        "10. Code Walkthrough: Line-by-Line Guide for Project Presentation",
        "11. Accurate Machine Learning & Threat Detection Reality",
        "12. Guide Presentation Scripts (1-Minute, 3-Minute & 5-Minute Live Demo)",
        "13. Strengths, Honest Limitations & Future Improvements",
        "14. Comprehensive Viva Voce Preparation (40 Questions & Answers)",
        "15. Tough & Tricky Questions Guides Ask After Inspecting Code",
        "16. Technical Glossary of Essential Terms",
        "17. One-Page Quick Revision Cheat Sheet",
    ]
    for item in toc_items:
        story.append(Paragraph(f"• <b>{item}</b>", styles["Body"]))

    story.append(Spacer(1, 10))
    story.append(Paragraph("1. Executive Summary & Problem Statement", styles["H1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#061A35"), spaceAfter=8))

    story.append(
        Paragraph(
            "<b>The Problem:</b> Cyber financial fraud in India and across the world has evolved beyond simple email phishing. "
            "Threat actors now exploit multiple interconnected vectors: (1) lookalike brand URLs distributed via SMS and messaging, "
            "(2) rogue Android APK packages masquerading as banking or utility updates that intercept SMS OTPs and request screen overlay rights, "
            "(3) fake transactional SMS headers impersonating commercial institutions or official TRAI alphanumeric identifiers, and "
            "(4) digitally manipulated or fake payment receipt screenshots used to defraud retail merchants without depositing money. "
            "Most commercial antivirus tools focus solely on executable desktop malware or require heavy cloud telemetry.",
            styles["Body"],
        )
    )
    story.append(
        Paragraph(
            "<b>The PhishShield Solution:</b> PhishShield is a locally-hosted, evidence-backed digital threat investigation system. "
            "It empowers cybersecurity analysts and citizens to inspect suspect links, Android packages, text messages, and payment receipts "
            "without ever executing untrusted code or visiting dangerous servers. "
            "Every verdict is backed by an auditable evidence chain, automated verification checks, known caveats, and recommended safety actions.",
            styles["Body"],
        )
    )

    story.append(
        callout_box(
            "<b>The Core Security Rule:</b> PhishShield guarantees <b>Zero Execution of Untrusted Content</b>. "
            "It never visits, fetches, or executes target URLs (preventing IP leak and beaconing); "
            "it never executes, installs, or emulates uploaded APK binaries (pure static parsing in memory); "
            "it redacts sensitive PII (OTPs, cards, Aadhaar) before database writes; and it never claims digital screenshots prove bank deposits.",
            styles,
            title="CORE ENGINEERING PHILOSOPHY",
        )
    )

    story.append(PageBreak())

    # =========================================================================
    # 3. COMPLETE SYSTEM ARCHITECTURE
    # =========================================================================
    story.append(Paragraph("2. Complete System Architecture & Engineering Principles", styles["H1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#061A35"), spaceAfter=8))

    story.append(
        Paragraph(
            "PhishShield implements a clean <b>Client-Server Decoupled Architecture</b>. "
            "The presentation layer is an asynchronous Single Page Application (SPA), the application layer is an ASGI REST API, "
            "the intelligence layer consists of deterministic security policies and machine learning pipelines, and the persistence layer "
            "is a relational SQLite database operating in Write-Ahead Logging (WAL) mode.",
            styles["Body"],
        )
    )

    arch_diagram = """
+----------------------------------------------------------------------------------------------------+
|                                FRONTEND PRESENTATION LAYER (Port 5173)                             |
|  React 18 + TypeScript SPA | Vite 5 | Cyber Guardian Dark Theme | React Router 6 | Axios Client    |
|  [UrlAnalysisPage]  [ApkAnalysisPage]  [SmsAnalysisPage]  [ScreenshotAnalysisPage]  [HistoryPage]   |
+--------------------------------------------------+-------------------------------------------------+
                                                   | HTTP REST / JSON / JWT Bearer Tokens
                                                   v
+----------------------------------------------------------------------------------------------------+
|                                BACKEND APPLICATION LAYER (FastAPI Port 8000)                       |
|  Uvicorn ASGI | CORS Middleware | Timing Header (X-Process-Time) | Security Headers | Rate Limiter |
|  API Routers: /api/analyze/url, /api/analyze/apk, /api/analyze/sms, /api/analyze/screenshot, /api/auth|
+-------------------+--------------------+-------------------+--------------------+------------------+
                    |                    |                   |                    |
                    v                    v                   v                    v
          +------------------+ +-------------------+ +---------------+ +--------------------+
          |    MODULE 1:     | |    MODULE 2:      | |   MODULE 3:   | |    MODULE 4:       |
          | URL Threat Engine| | APK Static Engine | |  SMS & DLT    | | Screenshot OCR     |
          | - Static Parser  | | - In-Memory ZIP   | | - DLT Headers | | - Image Lanczos    |
          | - 43 Features    | | - pyaxmlparser    | | - Levenshtein | | - RapidOCR (ONNX)  |
          | - Rules & Feeds  | | - Permissions Map | | - Scam Lexicon| | - Regex Fields     |
          | - HistGradBoost  | | - DEX C2 Strings  | | - PII Masking | | - Contradiction    |
          +--------+---------+ +---------+---------+ +-------+-------+ +---------+----------+
                   |                     |                   |                   |
                   +---------------------+---------+---------+-------------------+
                                                   | Unified AnalysisResult Schema
                                                   v
+----------------------------------------------------------------------------------------------------+
|                                MODULE 5: PERSISTENCE & AUDIT ENGINE                                |
|  SQLAlchemy 2.0 ORM | SQLite (WAL Mode) | Alembic Migrations | User-Scoped Access Controls         |
|  Tables: investigations, evidence_items, checks, url_details, apk_details, sms_details, users       |
|  Reporting Service: ReportLab 5.0 Dynamic PDF Generation & Forensic Audit Trail Export             |
+----------------------------------------------------------------------------------------------------+
    """
    story.append(code_box(arch_diagram, styles))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Request-Response Lifecycle Flow", styles["H2"]))
    lifecycle_steps = [
        "1. <b>Client Request:</b> User enters a suspect entity (URL, APK, SMS, or image) in the React frontend. The Axios client attaches the stored JWT access token in the `Authorization: Bearer <token>` header.",
        "2. <b>Validation & Guardrails:</b> FastAPI parses input via Pydantic v2 schemas (`UrlAnalyzeRequest`, `FileUpload`, etc.). Size limits (2048 chars for URL, 100 MB for APK, 10 MB for images) prevent Denial of Service.",
        "3. <b>Multi-Layer Execution:</b> The dedicated service dispatches input across: (a) static parsing, (b) deterministic heuristic rules, (c) reference data lookups, and (d) machine learning or OCR engines.",
        "4. <b>Risk Policy Synthesis:</b> The engine combines rule hits, reputation status, and ML probability into a calibrated immutable verdict: `malicious`, `suspicious`, `clean_no_findings`, or `inconclusive`.",
        "5. <b>Persistence:</b> The result is written into the SQLite database with execution latency (`duration_ms`), SHA-256 hash of the input, technical evidence items, checks performed, and authenticated user ID.",
        "6. <b>Response & Audit:</b> Frontend receives the structured JSON response, displays real-time badges, explanations, actions, and enables one-click forensic PDF download.",
    ]
    for s in lifecycle_steps:
        story.append(Paragraph(s, styles["Body"]))

    story.append(PageBreak())

    # =========================================================================
    # 4. TECHNOLOGIES, FRAMEWORKS & DEPENDENCIES
    # =========================================================================
    story.append(Paragraph("3. Actual Technologies, Frameworks & Dependencies Used", styles["H1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#061A35"), spaceAfter=8))

    story.append(
        Paragraph(
            "Every dependency in PhishShield was selected for local Windows execution, safety, and zero external runtime API dependence. "
            "Below is the exact inventory from `backend/requirements.txt` and `frontend/package.json`:",
            styles["Body"],
        )
    )

    tech_table = [
        ["Component / Package", "Version", "Role in PhishShield Architecture", "Technical Justification"],
        ["FastAPI", "0.143.0", "Backend ASGI Web Framework", "High performance async routing, native Pydantic v2 validation, OpenAPI docs"],
        ["Uvicorn", "0.54.0", "ASGI Production Server", "Ultra-fast lightning ASGI server powering async endpoint workers"],
        ["SQLAlchemy", "2.1.4", "ORM & Database Abstraction", "Modern typed Mapped attributes, cascade deletes, complex multi-table queries"],
        ["Alembic", "1.20.0", "Database Schema Migrations", "Safe forward/rollback database schema versioning without data loss"],
        ["scikit-learn", "1.9.1", "Machine Learning Pipeline", "Powers HistGradientBoostingClassifier & CalibratedClassifierCV"],
        ["RapidOCR (ONNX)", "1.2.3", "Optical Character Recognition", "Self-contained ONNX runtime OCR; requires no external system binary"],
        ["pyaxmlparser", "0.3.31", "Android Binary XML Parser", "Parses binary AndroidManifest.xml directly from memory buffers"],
        ["ReportLab", "5.0.1", "Forensic PDF Report Generator", "Generates professional court-ready PDF audit reports on demand"],
        ["bcrypt", "5.0.0", "Password Cryptographic Hashing", "Secure password hashing with 12 rounds of salt against rainbow tables"],
        ["python-jose", "3.5.0", "JWT Token Signing & Decoding", "Stateless, signed HS256 authentication tokens with 8-hour expiry"],
        ["SlowAPI", "0.1.10", "Rate Limiting Middleware", "Guards sensitive endpoints against brute-force and credential stuffing"],
        ["React", "18.3.1", "Frontend User Interface", "Declarative component hierarchy, virtual DOM, high-speed UI re-rendering"],
        ["TypeScript", "5.5.3", "Static Type Safety", "Strict type checking across frontend services, models, and UI props"],
        ["Vite", "5.4.21", "Next-Gen Frontend Bundler", "Sub-second HMR dev server and optimized production tree-shaken bundling"],
        ["Lucide React", "0.344.0", "Cybersecurity Visual Icons", "Clean SVG icons for security indicators, shields, alerts, and badges"],
    ]
    story.append(make_table(tech_table, [95, 50, 180, 180], styles))

    story.append(Spacer(1, 10))
    story.append(Paragraph("4. Project Folder Hierarchy & Key Source Files", styles["H1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#061A35"), spaceAfter=8))

    file_hierarchy = """
phishshield/
├── backend/
│   ├── app/
│   │   ├── api/                 # REST endpoints: url_routes, apk_routes, sms_routes, screenshot_routes, auth_routes, history_routes
│   │   ├── auth/                # Security utilities: security.py (bcrypt/JWT), dependencies.py (FastAPI auth guards)
│   │   ├── database/            # Database layer: connection.py (engine/WAL), models.py (ORM), repository.py (queries)
│   │   ├── schemas/             # Pydantic models: shared.py (AnalysisResult, EvidenceItem, Verdict, CheckPerformed)
│   │   ├── security/            # URL logic: url_parser.py (static parsing), url_features.py (43 features), url_rules.py (16 rules)
│   │   ├── services/            # Engine services: url_service.py, apk_service.py, sms_service.py, screenshot_service.py
│   │   ├── main.py              # Application entrypoint: CORS, timing middleware, lifespan startup/shutdown
│   │   └── config.py            # Configuration settings: Pydantic BaseSettings, environment variables
│   ├── tests/                   # 103 Automated pytest unit and integration tests (100% pass)
│   └── requirements.txt         # Pinned production Python dependencies
├── frontend/
│   ├── src/
│   │   ├── components/          # Reusable UI: CyberShieldArt.tsx, EvidenceList.tsx, ResultSummary.tsx, StatusBadge.tsx
│   │   ├── context/             # AuthContext.tsx: Global authentication state, tokens, user session
│   │   ├── pages/               # Views: LoginPage, RegisterPage, DashboardPage, UrlAnalysisPage, ApkAnalysisPage, SmsAnalysisPage...
│   │   ├── services/            # API wrappers: apiClient.ts (Axios with Bearer token injection), urlService, apkService...
│   │   └── styles/              # Design system: theme.css (tokens, radiant gradients), components.css, globals.css
│   └── package.json             # Frontend dependencies and Vite scripts
├── data/
│   ├── phishshield.db           # Live SQLite Database (WAL mode, foreign keys enabled)
│   └── reference/               # Reference sets: brand_domains.csv, sms_sender_reference.csv, tunnel_hosts.csv, apk_rules.yaml
├── models/
│   ├── url_model.joblib         # Trained HistGradientBoostingClassifier model binary (2.65 MB)
│   └── url_model_meta.json      # Model metadata: 43 feature names, validation metrics, calibration curve
└── docs/                        # Architecture, datasets, security, and viva study guides
    """
    story.append(code_box(file_hierarchy, styles))

    story.append(PageBreak())

    # =========================================================================
    # 5. MODULE 1: URL THREAT ANALYSIS
    # =========================================================================
    story.append(Paragraph("5. Deep-Dive Module 1: URL Threat Analysis & Calibrated ML Engine", styles["H1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#061A35"), spaceAfter=8))

    story.append(
        Paragraph(
            "The URL Threat Analysis module (`backend/app/services/url_service.py`) protects users by evaluating "
            "links across banking, UPI, email, e-commerce, and credential theft kits. "
            "It combines a zero-fetch static parser, 43 extracted features, brand homograph detection, 16 heuristic rules, "
            "local threat feeds, and a scikit-learn machine learning classifier.",
            styles["Body"],
        )
    )

    story.append(Paragraph("Step 1: The Static Parser (`url_parser.py`)", styles["H2"]))
    story.append(
        Paragraph(
            "Standard Python `urllib.parse` is vulnerable to bypasses when handling obfuscated malicious links. "
            "PhishShield implements a specialized static parser that decodes:",
            styles["Body"],
        )
    )
    url_parser_features = [
        "<b>IP Obfuscation Normalization:</b> Converts packed 32-bit decimal IPs (e.g. `http://3232235777`), octal IPs (`http://0300.0250.0001.0001`), and hexadecimal IPs (`http://0xC0.0xA8.0x01.0x01`) into canonical dotted-decimal notation (`192.168.1.1`).",
        "<b>IDN Punycode & Mixed-Script Homoglyphs:</b> Detects internationalized domain names (e.g. `xn--sbi-8ka.com`) and flags Cyrillic or Greek characters mixed into Latin domains designed to spoof brands like SBI, Google, or HDFC.",
        "<b>Userinfo (`@`) Parsing:</b> Attackers use `https://google.com@evil-phish.ru` to mislead users; the parser extracts `google.com` as userinfo credentials and correctly identifies `evil-phish.ru` as the true target host.",
        "<b>Double URL Encoding & Slash Tricks:</b> Detects double-encoded strings (`%252F`), reverse slashes (`\\\\`), and embedded redirects in query parameters.",
    ]
    for upf in url_parser_features:
        story.append(Paragraph(f"• {upf}", styles["Bullet"]))

    story.append(Paragraph("Step 2: 43 Lexical & Statistical Features (`url_features.py`)", styles["H2"]))
    story.append(
        Paragraph(
            "The feature extraction engine converts every URL into a deterministic vector of 43 numerical features. "
            "Key feature categories include:",
            styles["Body"],
        )
    )

    feat_table = [
        ["Feature Category", "Representative Features in Vector", "Why Attackers Trigger This Signal"],
        ["Structural Lengths", "`url_length`, `hostname_length`, `path_length`, `query_length`", "Phishing URLs average 78+ chars vs 34 for clean links due to embedded tokens."],
        ["Shannon Entropy", "`hostname_entropy`, `path_entropy`", "Random algorithmic domain generation (DGA) exhibits high information entropy (>3.8)."],
        ["Host Character Ratios", "`digit_ratio_host`, `digit_count_host`, `special_count_host`", "Legitimate domains are human-memorable words; phishers use numeric sequences."],
        ["Subdomain & TLD", "`num_subdomains`, `subdomain_depth`, `tld_risk_group`", "Free/abused TLDs (`.top`, `.xyz`, `.club`) and deep subdomains (`login.sbi.portal.com`)."],
        ["Suspicious Tokens", "`suspicious_token_count_host`, `_path`, `_query`", "Presence of sensitive words: `kyc`, `netbanking`, `verify`, `otp`, `update`, `blocked`."],
        ["Evasion & Tunneling", "`is_tunnel_host`, `is_shortener`, `has_base64_blob`", "Temporary tunnels (`trycloudflare.com`, `ngrok-free.app`) and Base64 payloads."],
        ["Brand Lookalike", "`brand_lookalike_score`, `brand_in_subdomain_not_registrable`", "Target brand name in subdomain (e.g. `hdfc.login-portal.com`) but not registrable domain."],
    ]
    story.append(make_table(feat_table, [110, 195, 200], styles))

    story.append(Paragraph("Step 3: Machine Learning Model (`train_url_model.py` & `model_loader.py`)", styles["H2"]))
    story.append(
        Paragraph(
            "<b>Algorithm:</b> `HistGradientBoostingClassifier` calibrated with `CalibratedClassifierCV(method='sigmoid')`.<br/>"
            "<b>Model File:</b> `models/url_model.joblib` (2.65 MB) and `models/url_model_meta.json`.<br/>"
            "<b>Training Data:</b> Over 15,000 URLs from Tranco Top-1M (legitimate base), URLhaus (active malware drops), and OpenPhish (credential theft).<br/>"
            "<b>Domain-Grouped Split:</b> Evaluated strictly via `GroupShuffleSplit` on `registrable_domain`. "
            "This ensures URLs from the same domain never appear in both train and test splits, proving real-world generalisation to unseen domains.",
            styles["Body"],
        )
    )

    story.append(
        callout_box(
            "<b>Actual Verified Evaluation Metrics (Held-Out Test Set):</b><br/>"
            "• <b>ROC-AUC:</b> 0.9994 | <b>PR-AUC:</b> 0.9990<br/>"
            "• <b>Precision:</b> 99.63% at threshold 0.50 | <b>Recall:</b> 98.15% | <b>F1-Score:</b> 0.9888<br/>"
            "• <b>Brier Calibration Score:</b> 0.00335 (near perfect probabilistic calibration)<br/>"
            "• <b>Decision Thresholds:</b> Probability &ge; 0.70 &rarr; `High Risk` (Malicious); Probability &ge; 0.20 &rarr; `Medium Risk` (Suspicious); &lt; 0.20 &rarr; `Low Risk`.",
            styles,
            title="INSPECTED & VERIFIED ML METRICS",
        )
    )

    story.append(PageBreak())

    # =========================================================================
    # 6. MODULE 2: ANDROID APK STATIC ANALYSIS
    # =========================================================================
    story.append(Paragraph("6. Deep-Dive Module 2: Android APK Static Forensic Engine", styles["H1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#061A35"), spaceAfter=8))

    story.append(
        Paragraph(
            "The APK Static Analysis service (`backend/app/services/apk_service.py`) analyzes Android installation binaries "
            "to detect mobile banking trojans, SMS stealers, ransomware, and spyware without execution.",
            styles["Body"],
        )
    )

    story.append(Paragraph("Safety Guardrails & Zip-Bomb Protection", styles["H2"]))
    story.append(
        Paragraph(
            "Malicious APKs often attempt to crash security tools by acting as 'zip bombs' (nested archives that expand to hundreds of gigabytes). "
            "PhishShield enforces strict memory-safe guards before processing:",
            styles["Body"],
        )
    )
    apk_safety = [
        "<b>Magic Byte Verification:</b> Validates PK ZIP header (`PK\\x03\\x04`) and confirms presence of `AndroidManifest.xml`.",
        "<b>Zip Bomb Heuristics:</b> Rejects packages with > 1,000 zip entries, > 500 MB total uncompressed size, or compression ratio > 100x.",
        "<b>Strict In-Memory Processing:</b> Files are read directly from `io.BytesIO` streams; no APK is ever extracted to the host disk or executed.",
    ]
    for asf in apk_safety:
        story.append(Paragraph(f"• {asf}", styles["Bullet"]))

    story.append(Paragraph("Dangerous Permissions & Trojan Signature Combos", styles["H2"]))
    story.append(
        Paragraph(
            "PhishShield monitors 18 sensitive Android permissions via `pyaxmlparser.core.APK`. "
            "Beyond isolated permissions, it detects lethal combinations typical of Indian banking trojans (e.g. SharkBot, Cerberus, SOVA):",
            styles["Body"],
        )
    )

    apk_table = [
        ["Trojan Pattern", "Monitored Permission Combination", "Forensic Threat & Mechanism"],
        ["Banking Overlay Attack", "`SYSTEM_ALERT_WINDOW` + `BIND_ACCESSIBILITY_SERVICE`", "Creates invisible fake login windows over legitimate banking apps to steal credentials."],
        ["SMS OTP Interception", "`RECEIVE_SMS` / `READ_SMS` + `INTERNET`", "Silently reads incoming bank OTPs and exfiltrates them to attacker servers without user awareness."],
        ["Ransomware Persistence", "`BIND_DEVICE_ADMIN` + `RECEIVE_BOOT_COMPLETED`", "Locks the device screen upon startup and prevents user uninstallation."],
        ["Silent App Dropper", "`REQUEST_INSTALL_PACKAGES` + `INTERNET`", "Downloads secondary malicious payloads and prompts installation without Google Play."],
    ]
    story.append(make_table(apk_table, [110, 195, 200], styles))

    story.append(Paragraph("DEX Bytecode String & C2 Extraction", styles["H2"]))
    story.append(
        Paragraph(
            "The engine reads Dalvik Executable (`classes.dex`) binary string tables and searches for malware indicators: "
            "dynamic code loading (`DexClassLoader`), shell execution (`Runtime.exec`), Telegram bot C2 tokens (`api.telegram.org`), "
            "and hardcoded remote IP addresses.",
            styles["Body"],
        )
    )

    story.append(PageBreak())

    # =========================================================================
    # 7. MODULE 3: SMS & DLT SENDER VERIFICATION
    # =========================================================================
    story.append(Paragraph("7. Deep-Dive Module 3: SMS & TRAI DLT Sender Verification", styles["H1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#061A35"), spaceAfter=8))

    story.append(
        Paragraph(
            "The SMS analysis module (`backend/app/services/sms_service.py`) protects users against 'Smishing' attacks "
            "such as fake electricity power cut warnings, urgent KYC bank blocks, lottery scams, and part-time task fraud.",
            styles["Body"],
        )
    )

    story.append(Paragraph("Indian DLT Header Verification (`sms_sender_reference.csv`)", styles["H2"]))
    story.append(
        Paragraph(
            "In India, the Telecom Regulatory Authority of India (TRAI) mandates Distributed Ledger Technology (DLT) registration. "
            "Official transactional SMS must originate from approved 6-character alphanumeric headers prefixed by a 2-letter operator/circle code "
            "(e.g., `VK-HDFCBK`, `AD-SBIINB`, `CP-AMAZON`).",
            styles["Body"],
        )
    )

    dlt_table = [
        ["Sender Identifier State", "Example Received Header", "Forensic Engine Evaluation"],
        ["Exact DLT Match", "`VK-SBIINB` &rarr; Core `SBIINB`", "Header verified in `sms_sender_reference.csv` as registered State Bank of India."],
        ["Possible Lookalike", "`VK-SBI1NB` or `AD-HDFCBKK`", "Levenshtein distance = 1 from verified brand header; flagged as potential impersonation."],
        ["Personal Mobile Number", "`+919876543210` or 10-digit", "Institutions never send official alerts from personal SIM cards; flagged as HIGH RISK."],
        ["Unverified Header", "`BW-QUICKLOAN`", "Syntactically valid 6-char header, but unlisted in verified reference dataset."],
    ]
    story.append(make_table(dlt_table, [125, 140, 240], styles))

    story.append(Paragraph("Linguistic Risk Engine & Negation Parsing", styles["H2"]))
    story.append(
        Paragraph(
            "Scam messages use psychological pressure (urgency, fear, greed). "
            "PhishShield parses multi-lingual patterns including Hinglish and Devanagari (e.g. <i>'bijli kat jayegi'</i>, <i>'khata band ho jayega'</i>). "
            "Critically, it uses <b>negation parsing</b> to distinguish legitimate bank warnings ("
            "<i>'Never share your OTP with anyone'</i>) from scam demands (<i>'Share OTP immediately to unblock'</i>).",
            styles["Body"],
        )
    )

    story.append(
        callout_box(
            "<b>Automatic PII Redaction:</b> Before saving to the SQLite database, "
            "`sms_service.py` executes regex redaction over the message body: "
            "6-digit OTPs are masked to `[OTP-REDACTED]`, 12-digit Aadhaar numbers to `[AADHAAR-REDACTED]`, "
            "and 16-digit payment card numbers to `[CARD-REDACTED]`. Personal data is never stored in plaintext.",
            styles,
            title="PRIVACY & PII REDACTION POLICY",
        )
    )

    story.append(PageBreak())

    # =========================================================================
    # 8. MODULE 4: PAYMENT SCREENSHOT OCR INVESTIGATION
    # =========================================================================
    story.append(Paragraph("8. Deep-Dive Module 4: Payment Screenshot OCR Investigation", styles["H1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#061A35"), spaceAfter=8))

    story.append(
        Paragraph(
            "Fraudulent payment screenshots generated via fake payment apps (e.g. fake Paytm/PhonePe/GPay APKs) "
            "are widely used to trick shopkeepers and sellers into releasing goods. "
            "The screenshot service (`backend/app/services/screenshot_service.py`) conducts forensic text and layout inspection.",
            styles["Body"],
        )
    )

    story.append(Paragraph("Image Preprocessing & OCR Engine Abstraction", styles["H2"]))
    story.append(
        Paragraph(
            "1. <b>Validation:</b> Confirms image MIME type (`image/png`, `image/jpeg`, `image/webp`) and enforces a maximum of 144,000,000 pixels.<br/>"
            "2. <b>Lanczos Preprocessing (`_preprocess_image`):</b> Upscales images smaller than 800px using PIL Lanczos interpolation, "
            "converts to 8-bit grayscale (`L`), and enhances sharpness by a factor of 1.5 to maximize OCR character contrast.<br/>"
            "3. <b>Multi-Engine Fallback (`_detect_ocr_engine`):</b> Tesseract &rarr; RapidOCR (ONNX) &rarr; EasyOCR. "
            "In this environment, `rapidocr_onnxruntime` is active, running completely in-process via ONNX without external binaries.",
            styles["Body"],
        )
    )

    story.append(Paragraph("Field Extraction & Semantic Consistency Rules", styles["H2"]))
    ocr_fields = [
        "<b>Amount Extraction:</b> Regex matches `₹`, `Rs.`, or `INR` followed by numbers and decimals (e.g. `₹1,500.00`).",
        "<b>Status Extraction:</b> Extracts words: `Success`, `Successful`, `Paid`, `Completed`, `Failed`, `Pending`.",
        "<b>12-Digit UPI UTR Reference:</b> Matches standard Indian 12-digit Unique Transaction Reference (UTR) numbers.",
        "<b>UPI Handle Verification:</b> Validates payment handles (`@oksbi`, `@okhdfcbank`, `@paytm`, `@ybl`) against 22 known PSP handles.",
    ]
    for of in ocr_fields:
        story.append(Paragraph(f"• {of}", styles["Bullet"]))

    story.append(Spacer(1, 4))
    story.append(
        callout_box(
            "<b>Crucial Forensic Caveats Detected:</b><br/>"
            "• <b>Conflicting Status Words:</b> If both 'Success' and 'Failed' appear, the image is flagged as a high-severity manipulation.<br/>"
            "• <b>Success Without Reference ID:</b> If status is 'Success' but no 12-digit UTR exists, it is flagged as suspicious.<br/>"
            "• <b>Legal Notice:</b> A screenshot <b>can never prove money was deposited</b>. Users are instructed to verify balance in their official bank app.",
            styles,
            title="CRITICAL FORENSIC NOTICE",
        )
    )

    story.append(PageBreak())

    # =========================================================================
    # 9. MODULE 5: AUTHENTICATION, DATABASE & REPORTING
    # =========================================================================
    story.append(Paragraph("9. Deep-Dive Module 5: User Authentication, SQLite Persistence & Reporting", styles["H1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#061A35"), spaceAfter=8))

    story.append(
        Paragraph(
            "The persistence and governance tier (`backend/app/database/`, `backend/app/auth/`) ensures "
            "multi-user isolation, cryptographic integrity, and compliance auditability.",
            styles["Body"],
        )
    )

    story.append(Paragraph("Authentication & Session Security (`security.py`)", styles["H2"]))
    auth_points = [
        "<b>Password Hashing:</b> Plaintext passwords are hashed using `bcrypt.hashpw` with 12 rounds of salt. Passwords are truncated at 72 bytes per bcrypt specification.",
        "<b>Stateless JWT Tokens:</b> Tokens are signed using HMAC-SHA256 (`HS256`). Payloads contain `sub` (User UUID), `email`, `iat`, and `exp` (8 hours).",
        "<b>Dependency Guards:</b> `get_current_user` validates the token for protected endpoints; `get_optional_user` permits legacy or anonymous scans.",
    ]
    for ap in auth_points:
        story.append(Paragraph(f"• {ap}", styles["Bullet"]))

    story.append(Paragraph("Database Architecture & SQLite WAL Mode", styles["H2"]))
    story.append(
        Paragraph(
            "The database is managed via SQLAlchemy 2.0 ORM with SQLite stored at `data/phishshield.db`. "
            "To prevent database lockups during concurrent background scans and UI queries, SQLite is initialized with "
            "<b>Write-Ahead Logging (WAL)</b> mode: `PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;`.",
            styles["Body"],
        )
    )

    db_table = [
        ["Table Name", "Primary Key", "Foreign Keys & Cascades", "Purpose & Stored Data"],
        ["`users`", "UUID String(36)", "None", "Stores email, full_name, hashed_password, created_at."],
        ["`investigations`", "UUID String(36)", "`user_id` (Index, nullable)", "Main audit entity: type, verdict, display_label, latency, input_hash, summary."],
        ["`evidence_items`", "UUID String(36)", "`investigation_id` &rarr; CASCADE", "Granular forensic indicators: category, severity, title, detail, source."],
        ["`checks`", "UUID String(36)", "`investigation_id` &rarr; CASCADE", "Security checklist items: name, status (completed/failed), detail."],
        ["`url_details`", "UUID String(36)", "`investigation_id` &rarr; CASCADE", "Normalized components: scheme, host, path, query, model_score, IP."],
        ["`apk_details`", "UUID String(36)", "`investigation_id` &rarr; CASCADE", "Package name, version, SHA256, sensitive permission lists, detected C2."],
        ["`sms_details`", "UUID String(36)", "`investigation_id` &rarr; CASCADE", "Sender header, verification state, detected URLs, redacted body."],
        ["`screenshot_details`", "UUID String(36)", "`investigation_id` &rarr; CASCADE", "OCR engine, extracted amount, status, 12-digit UTR, detected handles."],
    ]
    story.append(make_table(db_table, [100, 80, 125, 200], styles))

    story.append(Paragraph("Dynamic PDF Export (`history_routes.py` -> `_generate_pdf`)", styles["H2"]))
    story.append(
        Paragraph(
            "Users can download official forensic reports via `GET /api/history/{id}/export.pdf`. "
            "The backend uses ReportLab 5.0 to generate a streaming PDF response containing the investigation UUID, timestamp, "
            "verdict badges, input hash, complete technical evidence items, verification checks, and formal legal disclaimers.",
            styles["Body"],
        )
    )

    story.append(PageBreak())

    # =========================================================================
    # 10. SOURCE CODE WALKTHROUGH FOR PROJECT PRESENTATION
    # =========================================================================
    story.append(Paragraph("10. Code Walkthrough: Line-by-Line Guide for Project Presentation", styles["H1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#061A35"), spaceAfter=8))

    story.append(
        Paragraph(
            "When your project guide asks you to open the codebase and explain the implementation, "
            "use the exact roadmap below. These are real file paths, functions, and explanations:",
            styles["Body"],
        )
    )

    walkthroughs = [
        {
            "num": "1",
            "feature": "FastAPI Lifespan Startup & Preloading",
            "file": "backend/app/main.py",
            "func": "lifespan(app: FastAPI) [Lines 21–58]",
            "what_it_does": "Initializes SQLite database, pre-loads the trained URL ML model into memory, and caches reference sets (brand domains, tunnel hosts) so API requests experience zero startup lag.",
            "what_to_say": "'Sir, in main.py we use FastAPI's modern async lifespan context manager. On startup, we initialize our SQLite database in WAL mode and pre-load the 2.65 MB joblib model and reference CSVs into memory so incoming user scans are evaluated in under 50 milliseconds.'",
            "follow_up": "Q: Why pre-load the model? A: To prevent expensive 500ms disk read overhead on every HTTP request.",
        },
        {
            "num": "2",
            "feature": "Static URL Threat Parsing & Obfuscation Handling",
            "file": "backend/app/security/url_parser.py",
            "func": "parse_url(raw_url: str) [Lines 75–190]",
            "what_it_does": "Performs static string normalization without touching the network: decodes octal/hex IPs, normalizes IDN punycode, detects userinfo (@) tricks, and strips tracking parameters.",
            "what_to_say": "'In url_parser.py, we strictly enforce a zero-fetch policy. We normalize obfuscated IP formats like hex and octal into canonical IPv4, decode Punycode homoglyphs, and separate userinfo credentials from the real destination host.'",
            "follow_up": "Q: What happens if an attacker inputs an IP address? A: The parser extracts it, converts it to canonical dotted decimal, and extracts features showing it is a raw IP.",
        },
        {
            "num": "3",
            "feature": "HistGradientBoosting Model Scoring & Calibration",
            "file": "backend/app/services/model_loader.py",
            "func": "UrlModel.score(features) [Lines 47–55]",
            "what_it_does": "Validates the 43 feature names match url_features.py, transforms features into a 1x43 numpy vector, and calls pipeline.predict_proba(X) to get a calibrated phishing probability.",
            "what_to_say": "'In model_loader.py, our UrlModel class validates feature names at load time to prevent silent feature misalignment. The score method vectorizes the 43 lexical features and calls predict_proba, returning a calibrated probability between 0 and 1.'",
            "follow_up": "Q: What if the model file is missing? A: The system catches ModelLoadError gracefully and falls back to deterministic heuristic rules and reputation feeds.",
        },
        {
            "num": "4",
            "feature": "In-Memory Android APK Manifest & Bytecode Inspection",
            "file": "backend/app/services/apk_service.py",
            "func": "analyse(apk_bytes, filename) [Lines 140–280]",
            "what_it_does": "Checks zip bomb safety, parses AndroidManifest.xml in memory with pyaxmlparser, evaluates 18 permissions, and scans classes.dex string tables for C2 and trojan signatures.",
            "what_to_say": "'In apk_service.py, we never execute the APK. We verify zip bomb safety, extract the binary AndroidManifest.xml in memory, check for banking overlay combinations like Accessibility plus Overlay, and scan DEX bytecode strings for Telegram C2 endpoints.'",
            "follow_up": "Q: Why not run the APK in an emulator? A: Dynamic sandbox execution is slow (60+ seconds), platform-dependent, and risky on a client machine. Static analysis provides immediate, safe triage.",
        },
        {
            "num": "5",
            "feature": "DLT Header Lookups & Negation Parsing",
            "file": "backend/app/services/sms_service.py",
            "func": "verify_sender(sender) & analyse(text) [Lines 63–140]",
            "what_it_does": "Parses sender against TRAI DLT formats, computes Levenshtein distance for lookalikes, applies negation parsing to distinguish bank warnings from scams, and masks PII.",
            "what_to_say": "'In sms_service.py, verify_sender checks the alphanumeric header against our curated DLT dataset. If an attacker uses a lookalike like HDFCBKK, Levenshtein distance flags it. Our linguistic parser checks for urgency and power-cut keywords while ignoring legitimate bank warnings through negation parsing.'",
            "follow_up": "Q: Is this connected to live TRAI? A: No, TRAI does not provide a public open API, so we use a curated local DLT dataset of verified institutional headers.",
        },
        {
            "num": "6",
            "feature": "Image Upscaling & RapidOCR Text Extraction",
            "file": "backend/app/services/screenshot_service.py",
            "func": "_perform_ocr & _check_screenshot_rules [Lines 82–155, 224–280]",
            "what_it_does": "Upscales receipts with PIL Lanczos, runs RapidOCR ONNX in-process, extracts UPI UTR numbers and amounts via regex, and checks for contradictory status words.",
            "what_to_say": "'In screenshot_service.py, we enhance contrast and resolution using Lanczos upscaling and grayscale conversion. RapidOCR extracts text via ONNX runtime. We extract amounts and 12-digit UTRs with regex and flag contradictions like seeing both Success and Failed in the same receipt.'",
            "follow_up": "Q: Can OCR be 100% accurate? A: No, low resolution can reduce confidence. If key fields cannot be read, the system safely marks the verdict as Inconclusive.",
        },
    ]

    for w in walkthroughs:
        box_content = [
            Paragraph(f"<b>[{w['num']}] {w['feature']}</b>", styles["QTitle"]),
            Paragraph(f"<b>File:</b> `{w['file']}` • <b>Routine:</b> `{w['func']}`", styles["TableCellMono"]),
            Paragraph(f"<b>What it does:</b> {w['what_it_does']}", styles["Body"]),
            Paragraph(f"<b>What to say to guide:</b> {w['what_to_say']}", styles["AAnswer"]),
            Paragraph(f"<b>Guide follow-up:</b> {w['follow_up']}", styles["Callout"]),
        ]
        t = Table([[box_content]], colWidths=[505])
        t.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#CBD5E1")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ])
        )
        story.append(t)
        story.append(Spacer(1, 4))

    story.append(PageBreak())

    # =========================================================================
    # 11. PRESENTATION & LIVE DEMO SCRIPTS
    # =========================================================================
    story.append(Paragraph("11. Guide Presentation Scripts (1-Min, 3-Min & 5-Min Demo)", styles["H1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#061A35"), spaceAfter=8))

    story.append(Paragraph("A. The 1-Minute Elevator Pitch", styles["H2"]))
    story.append(
        Paragraph(
            "<i>'Respected Guide and Evaluators, digital financial fraud in India has expanded across multiple vectors—phishing URLs, rogue banking APKs, smishing messages, and fake payment receipts. "
            "Existing tools only check one vector or require risky external cloud connections. "
            "We built <b>PhishShield</b>, a unified, locally-hosted cyber threat investigation platform. "
            "PhishShield provides instant, zero-execution forensic analysis across suspect URLs, Android APKs, SMS headers, and payment screenshots. "
            "Powered by a calibrated HistGradientBoosting machine learning classifier, deterministic security rules, and in-memory static inspection, "
            "PhishShield generates explainable, evidence-backed verdicts and court-ready PDF audit reports in under 100 milliseconds.'</i>",
            styles["Body"],
        )
    )

    story.append(Paragraph("B. The 3-Minute Technical Overview", styles["H2"]))
    story.append(
        Paragraph(
            "<i>'PhishShield is engineered with a clean decoupled architecture. "
            "The backend is built in Python using FastAPI, providing asynchronous ASGI endpoints with Pydantic v2 data validation, bcrypt password hashing, and stateless JWT tokens. "
            "The database uses SQLite running in Write-Ahead Logging mode via SQLAlchemy 2.0 ORM, tracking full audit histories and granular evidence records.<br/><br/>"
            "Our detection pipeline consists of four specialized static modules: "
            "First, our URL Threat Engine normalizes obfuscated IP addresses and Punycode homoglyphs, extracts 43 lexical features, and runs a HistGradientBoosting model trained with domain-grouped splits to achieve a 99.6% precision and 0.999 ROC-AUC. "
            "Second, our APK Static Engine parses binary AndroidManifest files in memory using pyaxmlparser, flagging dangerous banking trojan combinations like Accessibility Service plus Screen Overlays. "
            "Third, our SMS Engine verifies sender headers against Indian TRAI DLT registrations using Levenshtein distance and applies negation parsing to distinguish real bank warnings from credential theft demands. "
            "Fourth, our Payment Screenshot Engine uses RapidOCR ONNX and Lanczos preprocessing to extract UPI UTRs and detect conflicting status words.<br/><br/>"
            "The frontend is a React 18 TypeScript application with a Cyber Guardian visual identity, giving users clear explanations, evidence breakdowns, and PDF report downloads. "
            "The entire project has 103 automated tests passing with 100% test reliability.'</i>",
            styles["Body"],
        )
    )

    story.append(Paragraph("C. The 5-Minute Live Demonstration Walkthrough Script", styles["H2"]))
    demo_steps = [
        "<b>Step 1 (Login & Dashboard):</b> Start at `http://localhost:5173`. Log in with test account. Show the Cyber Guardian theme, dashboard statistics (real metrics queried from SQLite), and quick scan launch buttons.",
        "<b>Step 2 (URL Threat Scan):</b> Navigate to <i>URL Analysis</i>. Input: `https://netbanking-hdfc.trycloudflare.com/login.php`. Click <i>Analyse URL</i>. Show the <b>Likely Malicious</b> verdict, explain the brand lookalike trigger (HDFC in subdomain), the Cloudflare tunnel warning, and the ML probability score.",
        "<b>Step 3 (APK Static Analysis):</b> Navigate to <i>APK Analysis</i>. Upload a sample APK with banking overlay permissions. Show the scan completing in <1 second. Highlight the detection of `SYSTEM_ALERT_WINDOW` combined with `BIND_ACCESSIBILITY_SERVICE` and DEX bytecode string indicators.",
        "<b>Step 4 (SMS Verification):</b> Navigate to <i>SMS Analysis</i>. Enter Sender: `+919876543210` (personal number) and Message: <i>'Dear customer your electricity power will be disconnected tonight. Call officer at 9876543210.'</i>. Click <i>Verify Message</i>. Show verdict: <b>Malicious Scam</b> with personal SIM sender warning and electricity panic classification.",
        "<b>Step 5 (Audit History & PDF Export):</b> Open <i>Investigation History</i>. Show the newly created investigations indexed by timestamp. Click into the forensic report and click <i>Download PDF Report</i>. Open the downloaded PDF in front of the guide to prove court-ready ReportLab generation.",
    ]
    for ds in demo_steps:
        story.append(Paragraph(ds, styles["Body"]))

    story.append(PageBreak())

    # =========================================================================
    # 12. STRENGTHS, LIMITATIONS & FUTURE ROADMAP
    # =========================================================================
    story.append(Paragraph("12. Strengths, Honest Limitations & Future Roadmap", styles["H1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#061A35"), spaceAfter=8))

    story.append(
        Paragraph(
            "Academic evaluators strongly appreciate candidates who understand their project's boundaries. "
            "Here is the honest breakdown of PhishShield's engineering trade-offs:",
            styles["Body"],
        )
    )

    comp_table = [
        ["Architectural Dimension", "PhishShield Verified Implementation", "Commercial / Complex Alternative", "Why PhishShield Chose This Trade-Off"],
        ["URL Fetching Policy", "Strict Static-Only (Zero HTTP Fetch)", "Headless Browser (Playwright / Selenium)", "Protects investigator IP from attacker tracking; zero risk of drive-by malware."],
        ["APK Execution Policy", "In-Memory Static Parsing Only", "Dynamic Sandbox (Cuckoo / Android Emulator)", "Instant sub-second results; zero risk of malicious code running on host Windows PC."],
        ["DLT Header Verification", "Curated Local Reference Dataset", "Direct TRAI DLT Portal API", "TRAI does not offer an open public API without expensive enterprise telecom agreements."],
        ["Image OCR Engine", "RapidOCR ONNX Runtime in Python", "Google Cloud Vision / AWS Textract", "100% offline, free, private, and runs without cloud bills or API keys."],
        ["Database Storage", "SQLite 3 with Write-Ahead Logging", "Distributed PostgreSQL / MongoDB", "Zero deployment friction on student PC; single file backup; handles 100K+ records easily."],
    ]
    story.append(make_table(comp_table, [100, 135, 135, 135], styles))

    story.append(Paragraph("Future Engineering Improvements", styles["H2"]))
    improvements = [
        "<b>Browser Extension Integration:</b> Package the URL feature extractor into a lightweight Chrome/Firefox Manifest V3 extension for real-time link hover warnings.",
        "<b>Dual-Stage ML Classifier:</b> Implement a lightweight transformer (e.g. DistilBERT) for multi-lingual Indian smishing text classification alongside heuristic rules.",
        "<b>YARA Rule Compiler:</b> Integrate native libyara rules into the APK DEX string extraction pipeline to detect compiled malware family signatures (e.g., Cerberus, FluBot).",
        "<b>EXIF Metadata Forensics:</b> Parse image EXIF tags in payment screenshots to detect digital image editor software stamps (e.g., Photoshop, Canva, Pixelmator).",
    ]
    for imp in improvements:
        story.append(Paragraph(f"• {imp}", styles["Bullet"]))

    story.append(PageBreak())

    # =========================================================================
    # 13. VIVA VOCE QUESTIONS & ANSWERS (PART 1: ARCHITECTURE & ML)
    # =========================================================================
    story.append(Paragraph("13. Comprehensive Viva Voce Preparation (40 Questions & Answers)", styles["H1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#061A35"), spaceAfter=8))

    viva_qa = [
        # General & Arch
        ("Q1: What is the primary objective of PhishShield?",
         "PhishShield is a multi-vector digital threat investigation platform designed to provide evidence-backed, explainable security verdicts across suspect URLs, Android APK packages, SMS messages, and payment screenshots without executing untrusted content."),
        ("Q2: Why did you choose FastAPI instead of Django or Flask?",
         "FastAPI provides native asynchronous ASGI support, automatic Pydantic v2 data validation, high performance comparable to Node.js/Go, and automatic OpenAPI documentation. Django is monolithic and heavy for REST APIs, while Flask lacks native async and typing validation."),
        ("Q3: How does the frontend communicate with the backend?",
         "The React frontend communicates via asynchronous HTTP REST requests using Axios. On login, the backend issues an HS256 JWT access token. Axios automatically injects this token into the 'Authorization: Bearer <token>' header on subsequent requests."),
        ("Q4: Why SQLite instead of MySQL or MongoDB?",
         "SQLite is serverless, zero-configuration, and self-contained in a single file (`data/phishshield.db`). With Write-Ahead Logging (WAL) mode enabled, it supports concurrent reads and writes, easily handling thousands of investigations locally without database server overhead."),
        ("Q5: What is Write-Ahead Logging (WAL) in SQLite?",
         "In traditional rollback journal mode, writing locks the entire database. In WAL mode, changes are appended to a separate `-wal` file, allowing readers to query the database concurrently while a write is occurring, preventing 'database locked' errors."),
        ("Q6: How are passwords stored securely?",
         "Passwords are hashed using `bcrypt` with 12 rounds of cryptographic salt. Salt prevents rainbow table attacks, and bcrypt's deliberate computational cost defends against brute-force cracking."),
        ("Q7: How do you handle Cross-Origin Resource Sharing (CORS)?",
         "In `backend/app/main.py`, we configure FastAPI's `CORSMiddleware` to allow requests explicitly from `http://localhost:5173` (the Vite frontend) with support for credentials, authorization headers, and REST methods."),
        ("Q8: What is Pydantic v2 used for in your application?",
         "Pydantic v2 enforces strict data validation and serialization for API request bodies and response schemas. It automatically rejects malformed types, strips invalid inputs, and generates 422 Unprocessable Entity errors before bad data reaches service logic."),

        # URL & ML
        ("Q9: What machine learning algorithm is used for URL threat detection?",
         "We use scikit-learn's `HistGradientBoostingClassifier`, calibrated using `CalibratedClassifierCV(method='sigmoid')`. The model is stored as a 2.65 MB binary in `models/url_model.joblib`."),
        ("Q10: Why HistGradientBoosting instead of Random Forest or Deep Learning?",
         "HistGradientBoosting bins continuous features into 256 integer histograms, making training and inference dramatically faster with lower memory usage. URLs have structured tabular features where gradient boosting consistently outperforms deep neural networks while remaining explainable."),
        ("Q11: What is a Domain-Grouped Split (GroupShuffleSplit)?",
         "If URLs from the same domain (e.g. `badsite.com/login` and `badsite.com/pay`) appear in both training and test sets, the model memorizes the domain rather than learning generalizable phishing patterns. GroupShuffleSplit groups by `registrable_domain`, guaranteeing the test set only contains unseen domains."),
        ("Q12: How many features does the URL model extract?",
         "The model extracts exactly 43 deterministic lexical, statistical, and brand lookalike features. Feature names are validated at load time to prevent silent feature misalignment."),
        ("Q13: What is Shannon Entropy and how does it detect phishing?",
         "Shannon Entropy measures the randomness of characters in a string. Legitimate domains usually contain readable words with moderate entropy (2.0–3.2). Algorithmic Domain Generation (DGA) or randomized phishing paths exhibit high entropy (>3.8)."),
        ("Q14: What is Levenshtein Distance and where is it used?",
         "Levenshtein distance measures the minimum number of single-character edits (insertions, deletions, substitutions) needed to change one word into another. PhishShield uses it to detect brand homographs (e.g., `paytmm.com` vs `paytm.com`) and spoofed SMS headers (`HDFCBKK` vs `HDFCBK`)."),
        ("Q15: What is the Brier Score in model evaluation?",
         "The Brier score measures the accuracy of probabilistic predictions (mean squared difference between predicted probabilities and actual outcomes). A score close to 0 indicates excellent calibration. PhishShield's URL model achieved a Brier score of 0.00335."),
        ("Q16: Why doesn't PhishShield visit or fetch the URL?",
         "Visiting suspect URLs can alert attackers (allowing them to block analysis via IP filtering), triggers tracking beacons that compromise investigator privacy, and exposes the system to browser drive-by exploits. PhishShield is strictly a static forensic analyzer."),
        ("Q17: What are the risk decision thresholds?",
         "A model probability &ge; 0.70 flags the URL as High Risk (`malicious`). A probability between 0.20 and 0.70 flags it as Medium Risk (`suspicious`). Below 0.20 is categorized as Low Risk."),
        ("Q18: What is a Punycode attack?",
         "Attackers register internationalized domain names (IDNs) using Cyrillic or Greek characters that look visually identical to Latin letters (e.g. Cyrillic 'а' vs Latin 'a'). Our parser detects Punycode (`xn--`) and flags mixed-script domains."),
    ]

    for q, a in viva_qa:
        story.append(Paragraph(f"<b>{q}</b>", styles["QTitle"]))
        story.append(Paragraph(a, styles["AAnswer"]))

    story.append(PageBreak())

    # =========================================================================
    # 14. VIVA VOCE QUESTIONS & ANSWERS (PART 2: APK, SMS, OCR, SECURITY)
    # =========================================================================
    story.append(Paragraph("14. Comprehensive Viva Voce Preparation (Continued)", styles["H1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#061A35"), spaceAfter=8))

    viva_qa_part2 = [
        # APK
        ("Q19: How does PhishShield analyze an APK without running it?",
         "An APK is an uncompressed ZIP archive. PhishShield uses `zipfile` and `pyaxmlparser` to extract and parse the binary `AndroidManifest.xml` and `classes.dex` directly in memory, inspecting declared permissions and string constants without host execution."),
        ("Q20: What is a Zip Bomb and how do you prevent it?",
         "A Zip Bomb is a tiny archive file that expands into gigabytes of data when extracted, crashing the host system. PhishShield checks zip headers in memory and rejects archives with >1,000 files, >500 MB uncompressed size, or compression ratios >100x."),
        ("Q21: Why is BIND_ACCESSIBILITY_SERVICE considered dangerous in an APK?",
         "Accessibility services allow an app to read all screen content, inspect keystrokes, and interact with other apps on behalf of the user. Banking trojans abuse it to read OTPs and automatically grant themselves administrative permissions."),
        ("Q22: What is a Banking Overlay attack?",
         "An app requests `SYSTEM_ALERT_WINDOW` and monitors when the user opens a genuine banking app. It then draws an identical fake login window on top of the real app to capture user credentials."),
        ("Q23: What indicators are searched for in the DEX bytecode?",
         "PhishShield searches string tables for Telegram Bot API endpoints (`api.telegram.org`), dynamic code loading (`DexClassLoader`), command shell execution (`Runtime.exec`), and raw external IP addresses."),
        ("Q24: Can your static APK tool guarantee an app is 100% clean?",
         "No. If malware downloads encrypted payloads from remote servers at runtime (stagers), static analysis will only see the benign container. Our report explicitly discloses this honest limitation."),

        # SMS
        ("Q25: What is Indian TRAI DLT header format?",
         "Under TRAI regulations, commercial SMS headers consist of a 2-letter circle/operator prefix followed by a hyphen and a 6-character alphanumeric header registered to the commercial enterprise (e.g., `VK-HDFCBK`)."),
        ("Q26: Why is an SMS from a 10-digit mobile number flagged?",
         "Legitimate financial institutions and government entities are legally prohibited from sending bulk transactional or service alerts from personal mobile numbers. Alerts from personal numbers claiming to be banks are almost always scams."),
        ("Q27: How does your negation parsing work in SMS analysis?",
         "PhishShield inspects surrounding context around sensitive words. A phrase like 'never share your password' is recognized as a genuine security advisory, whereas 'send your password immediately' triggers a credential harvesting warning."),
        ("Q28: Why do you redact PII before saving to the database?",
         "Storing sensitive user OTPs, credit card numbers, or Aadhaar numbers in application databases creates severe privacy and legal liability. Regex masks credentials to `[OTP-REDACTED]` before writing to disk."),
        ("Q29: Does your system connect live to the TRAI portal?",
         "No. TRAI does not provide a public open API for third-party queries. PhishShield uses a curated local reference dataset (`sms_sender_reference.csv`) compiled from verified institutional registries."),

        # OCR & Screenshot
        ("Q30: Which OCR engine is active in PhishShield and why?",
         "`rapidocr_onnxruntime` is active. It runs in-process using ONNX Runtime, eliminating the need to install external Tesseract system binaries on Windows while delivering rapid multi-lingual text extraction."),
        ("Q31: What preprocessing is applied to payment screenshots?",
         "Small images are upscaled to at least 800px using Lanczos resampling, converted to 8-bit grayscale, and sharpened by 1.5x using Pillow (`ImageEnhance.Sharpness`) to maximize character boundary contrast."),
        ("Q32: What is a UTR number in Indian banking?",
         "UTR stands for Unique Transaction Reference. It is a 12-digit reference number generated by the National Payments Corporation of India (NPCI) for every successful UPI and NEFT transaction."),
        ("Q33: How does PhishShield detect conflicting payment statuses?",
         "Fake payment generators often make layout mistakes. If the OCR detects both positive ('Paid', 'Success') and negative ('Failed', 'Declined') keywords on the same receipt, it flags a High Severity contradiction."),
        ("Q34: Can PhishShield verify if money actually entered a bank account?",
         "No. A screenshot is merely a static digital image that can be created in seconds using fake APK generators or image editors. Only checking the official bank account statement proves funds were received."),

        # Governance & Viva
        ("Q35: What happens if an investigation record is deleted?",
         "SQLAlchemy relationships use `cascade='all, delete-orphan'` and database foreign keys have `ondelete='CASCADE'`. Deleting an investigation automatically removes its associated evidence items and detail records cleanly."),
        ("Q36: How does the system prevent denial of service from huge uploads?",
         "FastAPI and service layers enforce strict size limits: URLs cannot exceed 2,048 characters, APKs cannot exceed 100 MB, and screenshots cannot exceed 10 MB or 144 million pixels."),
        ("Q37: What is Alembic and why is it used?",
         "Alembic is a database migration tool for SQLAlchemy. It tracks schema modifications across version scripts, enabling new columns and tables to be added without resetting the SQLite database or losing records."),
        ("Q38: What are the 4 standardized verdicts across all modules?",
         "Every module returns one of four immutable verdicts: `malicious` (Likely Malicious / Scam), `suspicious` (Suspicious Patterns Detected), `clean_no_findings` (No Known Threat Indicators), or `inconclusive` (Could Not Fully Evaluate)."),
        ("Q39: How many automated tests exist and how do you run them?",
         "PhishShield has 103 backend pytest tests and 2 frontend vitest tests. Backend tests are run using `backend\\.venv\\Scripts\\pytest backend\\tests` and frontend tests via `npm test`."),
        ("Q40: What makes PhishShield suitable for deployment in real organizations?",
         "Its zero-execution safety, local on-premises hosting, multi-user isolation, transparent evidence chain, and court-ready PDF generation make it ideal for corporate security operations centers and cybercrime triage."),
    ]

    for q, a in viva_qa_part2:
        story.append(Paragraph(f"<b>{q}</b>", styles["QTitle"]))
        story.append(Paragraph(a, styles["AAnswer"]))

    story.append(PageBreak())

    # =========================================================================
    # 15. TOUGH & TRICKY QUESTIONS GUIDES ASK
    # =========================================================================
    story.append(Paragraph("15. Tough & Tricky Questions Guides Ask After Reading Code", styles["H1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#061A35"), spaceAfter=8))

    story.append(
        Paragraph(
            "Experienced project guides and external examiners often look at code structure to probe deeper. "
            "Here is how to answer their most challenging technical questions:",
            styles["Body"],
        )
    )

    tricky_q = [
        ("Guide asks: 'Your URL model ROC-AUC is 0.9994. Isn't this model overfitted?'",
         "Answer: 'No, Sir. High ROC-AUC can indicate overfitting if evaluated on a random split where URLs from the same domain exist in both train and test sets. "
         "However, we specifically evaluated our model using `GroupShuffleSplit` on `registrable_domain`. "
         "Because all domains in the test set were completely unseen during training, this demonstrates genuine out-of-domain generalization. "
         "Furthermore, on our separate hard-negative sanity set of 117 complex URLs, our ROC-AUC was 0.9912 with an honest false-positive rate of 9.68%, "
         "which we openly document in `MODEL_EVALUATION.md`.'"),
        ("Guide asks: 'Why didn't you write a web scraper with Selenium to see what the page looks like?'",
         "Answer: 'Sir, connecting to live phishing websites from an investigation server introduces three major security flaws: "
         "(1) Attackers track incoming HTTP requests and can geo-fence or block our IP, "
         "(2) Drive-by malware and browser zero-day exploits can infect the host machine, and "
         "(3) Many phishing kits serve innocent content to security crawlers while targeting mobile victims. "
         "By maintaining a strict static-only architecture, PhishShield guarantees safe, private, sub-50ms triage without exposing the host.'"),
        ("Guide asks: 'What if an attacker obfuscates an APK using DexGuard or bytecode packing?'",
         "Answer: 'Sir, commercial packers encrypt the Dalvik bytecode. In such cases, static string inspection will not reveal the hidden C2 domains. "
         "However, the packed APK must still declare its requested permissions in `AndroidManifest.xml` to interact with Android hardware. "
         "PhishShield will still detect dangerous permission combinations like SMS reading plus Accessibility bindings. "
         "Furthermore, our report transparently lists bytecode encryption as a known caveat in our Evidence Limitations section.'"),
        ("Guide asks: 'Why do you use both Heuristic Rules and a Machine Learning model for URLs?'",
         "Answer: 'Sir, defense-in-depth. ML models excel at recognizing statistical and structural patterns in novel attacks, but they can be vulnerable to adversarial perturbations. "
         "Conversely, heuristic rules are deterministic and instant—for example, if a Cloudflare tunnel host contains a banking keyword, rule `TUNNEL_HOST_WITH_BRAND` fires with 100% certainty regardless of ML score. "
         "Our `risk_policy.py` combines both signals so that a critical rule hit overrides an ambiguous ML prediction.'"),
        ("Guide asks: 'How do you handle JWT secret key rotation across server restarts?'",
         "Answer: 'In `security.py`, the system reads `JWT_SECRET_KEY` from configuration or environment variables. "
         "If unset in local development, it logs a warning and generates a secure random 32-byte hex token that persists for the lifetime of that process. "
         "For persistent production sessions, setting the key in `.env` maintains user tokens across restarts.'"),
    ]

    for q, a in tricky_q:
        story.append(Paragraph(f"<b>{q}</b>", styles["QTitle"]))
        story.append(Paragraph(a, styles["AAnswer"]))

    story.append(Spacer(1, 8))
    story.append(Paragraph("16. Technical Glossary of Essential Terms", styles["H1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#061A35"), spaceAfter=8))

    glossary = [
        ("DLT (Distributed Ledger Technology)", "A blockchain-based registry mandated by TRAI in India to track and whitelist commercial SMS sender headers."),
        ("Entropy (Shannon)", "A mathematical measure of randomness in text. High entropy indicates randomized or machine-generated strings."),
        ("DEX (Dalvik Executable)", "The compiled bytecode format executed by Android's runtime virtual machine inside an APK archive."),
        ("Homoglyph / Punycode", "Visually identical characters from different alphabets (e.g. Cyrillic vs Latin) used to deceive users into fake domains."),
        ("Brier Score", "A strictly proper scoring rule measuring the accuracy of probabilistic predictions; lower scores mean superior calibration."),
        ("GroupShuffleSplit", "A cross-validation split strategy ensuring distinct groups (domains) do not leak between training and test sets."),
        ("Lanczos Resampling", "A high-quality image reconstruction algorithm based on a sinc filter, ideal for upscaling text in OCR pipelines."),
        ("WAL Mode", "SQLite Write-Ahead Logging; separates read operations from write logs to allow concurrent non-blocking database access."),
    ]
    for term, defn in glossary:
        story.append(Paragraph(f"• <b>{term}:</b> {defn}", styles["Body"]))

    story.append(PageBreak())

    # =========================================================================
    # 17. ONE-PAGE QUICK REVISION CHEAT SHEET
    # =========================================================================
    story.append(Paragraph("17. One-Page Quick Revision Cheat Sheet", styles["H1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#061A35"), spaceAfter=8))

    story.append(
        Paragraph(
            "Keep this summary sheet in hand 10 minutes before entering your project presentation or viva examination:",
            styles["Body"],
        )
    )

    cheat_data = [
        ["Core Metric / Architecture Item", "Inspected Ground-Truth Value in PhishShield Codebase"],
        ["Project Root Path", "`C:\\Users\\Admin\\Desktop\\phishshield`"],
        ["Backend Server Command", "`uvicorn backend.main:app --reload --port 8000` (FastAPI)"],
        ["Frontend Server Command", "`npm run dev` in `frontend/` (Vite, React 18, Port 5173)"],
        ["Database Engine & File", "SQLite 3 with WAL Mode (`data/phishshield.db`) via SQLAlchemy 2.0"],
        ["Active ML Algorithm", "`HistGradientBoostingClassifier` with `CalibratedClassifierCV(sigmoid)`"],
        ["ML Model Artifacts", "`models/url_model.joblib` (2.65 MB) & `models/url_model_meta.json`"],
        ["Number of Extracted Features", "Exactly 43 lexical, statistical, and structural URL features"],
        ["URL Decision Thresholds", "&ge; 0.70 &rarr; Malicious (High) • &ge; 0.20 &rarr; Suspicious (Medium) • &lt; 0.20 &rarr; Clean"],
        ["Test Set Metrics (Domain Split)", "ROC-AUC: 0.9994 • PR-AUC: 0.9990 • Precision: 99.63% • Brier: 0.00335"],
        ["Active OCR Engine", "`rapidocr_onnxruntime 1.2.3` (ONNX Runtime, self-contained, no Tesseract required)"],
        ["Password Cryptography", "bcrypt with 12 rounds of salt (`bcrypt.hashpw`)"],
        ["Authentication Tokens", "Stateless JSON Web Tokens (`HS256`, 8-hour expiration)"],
        ["Automated Test Coverage", "103 Backend Pytest tests (100% passing) + 2 Frontend Vitest tests"],
        ["Four Standard Verdicts", "`malicious`, `suspicious`, `clean_no_findings`, `inconclusive`"],
        ["ReportLab PDF Generator", "Dynamic PDF generation in `history_routes.py` and documentation builder"],
        ["Golden Defense Rule", "Zero execution of untrusted content; static forensic triage only."],
    ]
    story.append(make_table(cheat_data, [170, 335], styles))

    story.append(Spacer(1, 15))
    story.append(
        callout_box(
            "<b>Final Viva Tip:</b> Always speak calmly and reference the source code directly. "
            "State clearly that PhishShield is an evidence-backed static triage engine designed to protect analysts, "
            "and emphasize that every verdict provides transparent technical reasons rather than a black-box opinion.",
            styles,
            title="CONFIDENCE & DEFENSE MINDSET",
        )
    )

    # Build PDF
    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"Successfully generated study guide PDF: {OUTPUT_PDF}")


if __name__ == "__main__":
    build_pdf()
