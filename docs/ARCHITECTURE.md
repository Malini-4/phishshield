# PhishShield Architecture Documentation

PhishShield is a web-based phishing, scam, and digital-evidence investigation platform built with 5 decoupled modules, designed to give forensic investigators and end users clear, evidence-backed verdicts without executing untrusted content or faking security guarantees.

---

## 1. System Overview

```
                                  ┌───────────────────────────────┐
                                  │   React + Vite + TypeScript   │
                                  │      Frontend (Port 5173)     │
                                  └───────────────┬───────────────┘
                                                  │ HTTP Proxy / JSON
                                                  ▼
                                  ┌───────────────────────────────┐
                                  │      FastAPI Backend (8000)   │
                                  │   CORS, Rate Limit, Timings   │
                                  └───────────────┬───────────────┘
                                                  │
            ┌──────────────────────┬──────────────┴──────────────┬──────────────────────┐
            ▼                      ▼                             ▼                      ▼
    ┌───────────────┐      ┌───────────────┐             ┌───────────────┐      ┌───────────────┐
    │  Module 1:    │      │  Module 2:    │             │  Module 3:    │      │  Module 4:    │
    │  URL Threat   │      │  APK Static   │             │  SMS & DLT    │      │  Screenshot   │
    │  Analysis     │      │  Analysis     │             │  Verification │      │  OCR Analysis │
    └───────┬───────┘      └───────┬───────┘             └───────┬───────┘      └───────┬───────┘
            │                      │                             │                      │
            └──────────────────────┴──────────────┬──────────────┴──────────────────────┘
                                                  ▼
                                  ┌───────────────────────────────┐
                                  │   Module 5: Evidence Store    │
                                  │   SQLite + WAL + Alembic Migr │
                                  │   Dashboard & PDF Reports     │
                                  └───────────────────────────────┘
```

---

## 2. Core Modules Architecture

### Module 1: URL Threat Analysis
- **Parser (`url_parser.py`):** Pure static parser supporting hexadecimal, packed decimal, and octal IP obfuscations, IDN punycode normalization, mixed-script detection, userinfo (`@`) tricks, and double-encoding. Strictly **never connects to, renders, or downloads** the target URL.
- **Features (`url_features.py`):** Extracts 43 deterministic lexical features including entropy, token lengths, character distributions, and suspicious keywords.
- **Domain Checks (`domain_checks.py`):** Compares against curated brand domains (`brand_domains.csv`) and tunnel hosts (`tunnel_hosts.csv`) using Levenshtein distance on both ASCII and decoded Unicode representations.
- **Security Rules (`url_rules.py`):** Evaluates 16 high/medium/low severity deterministic rules.
- **ML Pipeline (`train_url_model.py`):** Calibrated `HistGradientBoostingClassifier` trained on verified feeds (Tranco, URLhaus, OpenPhish) with domain-grouped splits (`GroupShuffleSplit`) to prevent domain leakage.
- **Risk Policy (`risk_policy.py`):** Combines rule hits, reputation feeds, and model probability into an immutable verdict (`Likely malicious`, `Suspicious link`, `No known threat found`, `Could not verify`).

### Module 2: Android APK Static Analysis
- **Parser (`apk_service.py`):** Inspects binary `AndroidManifest.xml` and Dalvik bytecode `classes.dex` using `pyaxmlparser` and zip inspection.
- **Safety:** Rejects zip bombs (ratio > 100x or > 500 MB uncompressed), enforces 100 MB limits, and **never executes or emulates** the APK.
- **Rules:** Flags banking trojan patterns (SMS intercept + SMS send + boot persistence + screen overlay / accessibility), debuggable flags, cleartext IP endpoints, and package ID impersonation.

### Module 3: SMS and Sender-Header Scam Verification
- **Header Verifier (`sms_service.py`):** Matches sender identifiers against TRAI DLT alphanumeric registrations (`sms_sender_reference.csv`). Distinguishes registered headers, lookalikes, personal mobile numbers, and unverified senders.
- **Linguistic Engine:** Distinguishes genuine bank warnings ("Do not share OTP") from credential theft demands via negation parsing. Recognizes urgent disconnection threats, KYC expiration panics, lottery schemes, Hinglish, and Devanagari scam terms.
- **Privacy:** Masks sensitive 6-digit OTPs, 12-digit Aadhaar numbers, 16-digit cards, and phone numbers before database persistence.

### Module 4: Payment Screenshot OCR Investigation
- **OCR Engine (`screenshot_service.py`):** Integrates system Tesseract / pure-pip OCR engines with graceful degradation. Reports engine readiness at `/api/health`.
- **Field Extraction:** Regex parsing of amounts, statuses (Success/Paid/Failed), 12-digit UTR/UPI reference numbers, and UPI handles.
- **Consistency Checks:** Flags conflicting status words (e.g., both "Success" and "Failed" detected), "Success" without a transaction reference, or distorted geometry.
- **Forensic Disclaimer:** Always reminds the investigator that digital screenshots cannot confirm deposit receipt.

### Module 5: Investigation Reports and Audit History
- **Database (`models.py`, `repository.py`):** SQLite database initialized with WAL mode, foreign key enforcement, and migration tracking via Alembic.
- **Reporting (`history_routes.py`):** Full audit trail with paginated queries, search, deletion, dashboard analytics, and PDF export using ReportLab.

---

## 3. Technology Stack Summary

| Layer | Technologies |
| :--- | :--- |
| **Frontend** | React 18, Vite 5, TypeScript 5, React Router 6, lucide-react, Plain CSS with CSS tokens |
| **Backend** | Python 3.14 / 3.11+, FastAPI, Pydantic v2, Uvicorn, SlowAPI |
| **Database** | SQLite, SQLAlchemy 2.0, Alembic |
| **ML & Analytics** | scikit-learn (HistGradientBoosting), joblib, pandas, numpy |
| **OCR & PDF** | Pillow, ReportLab, pytesseract (optional system binary) |
