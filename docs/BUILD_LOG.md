# PhishShield Build Log

---

### Phase 1: Environment & Foundation
- Initialized isolated project directory `phishshield/`.
- Verified system versions: Python 3.14.0, Node v24.14.0, npm 11.9.0.
- Created Python virtual environment at `backend/.venv`.
- Created package initialization files for all app modules.
- Created SQLAlchemy models for investigations, evidence, checks, and all 4 module details with SQLite WAL mode and foreign key constraints.
- Configured Alembic migrations and executed `0001_initial` migration cleanly.
- Resolved Python 3.14 compatibility without greenlet dependency.

### Phase 2: URL Threat Analysis & ML
- Built `url_parser.py` (handles hex/octal/packed decimal IP forms, IDN punycode, userinfo tricks, double encoding).
- Built `url_features.py` with strict 43-feature contract (`FEATURE_NAMES`).
- Built reference datasets: `brand_domains.csv`, `tunnel_hosts.csv`, `sms_sender_reference.csv`.
- Built `prepare_datasets.py`: fetched verified live feeds from Tranco (3,000 domains), URLhaus (2,500 active URLs), OpenPhish (300 active URLs), hard-negative bank login portals, and synthetic kit patterns.
- Generated domain-grouped splits using `GroupShuffleSplit` on `registrable_domain` (70% train, 15% val, 15% test) to prevent cross-split leakage.
- Saved data quality report: `reports/data_quality.json`.
- Evaluated models in `compare_models.py`:
  - Logistic Regression (F1=0.9757, AUC=0.9926)
  - Random Forest (F1=0.9801, AUC=0.9958)
  - HistGradientBoosting (F1=0.9835, AUC=0.9955)
- Trained calibrated production model with `CalibratedClassifierCV` (sigmoid) on training set, tuned thresholds on validation set (`suspicious=0.200`, `malicious=0.700`).
- Saved model artifacts: `models/url_model.joblib` and `models/url_model_meta.json`.
- Evaluated held-out test set (765 URLs, 539 domains): ROC-AUC=0.9994, PR-AUC=0.9990, Precision at malicious threshold=1.0000.
- Evaluated real-world sanity set (117 URLs): ROC-AUC=0.9998, FPR on popular legitimate domains = 0.00%.
- Documented evaluation in `docs/MODEL_EVALUATION.md`.

### Phase 3: Android APK Static Analysis
- Implemented `apk_service.py` with static extraction via `pyaxmlparser` and raw zip entry inspection.
- Enforced zip bomb safeguards and file size limits (100 MB).
- Implemented banking trojan permission pattern detection, package spoofing rules, and cleartext IP C2 endpoint detection.

### Phase 4: SMS & Sender Verification
- Implemented `sms_service.py` with official Indian TRAI DLT alphanumeric header verification.
- Added negation handling to distinguish legitimate bank security warnings ("Do not share OTP") from fraud.
- Implemented financial lure, KYC, urgency, Hinglish, and Devanagari scam pattern rules.
- Added privacy redaction for OTPs, Aadhaar numbers, card numbers, and phone numbers.

### Phase 5: Payment Screenshot Investigation (OCR)
- Implemented `screenshot_service.py` with PIL contrast enhancement and OCR text extraction.
- Handled status extraction, 12-digit UTR verification, UPI handle verification, and status contradictions.
- Integrated runtime engine detection into `/api/health`.

### Phase 6: Persistence, Reports, and History
- Implemented repository layer in `repository.py` with search, filtering, pagination, and dashboard statistics.
- Implemented ReportLab PDF export at `/api/history/{id}/export.pdf`.
- Created feed refresh background script `backend/scripts/refresh_feeds.py` and populated 2,300 threat entries in SQLite.

### Phase 7: Frontend & Full Integration Testing
- Created React 18 + Vite 5 + TypeScript frontend with plain CSS tokens and Lucide icons.
- Built responsive layout with Sidebar, Topbar, StatusBadge, ResultSummary, EvidenceList, FileUpload, and EmptyState components.
- Built all 7 pages: Dashboard, URL Analysis, APK Analysis, SMS Analysis, Screenshot Analysis, History, and Report Details.
- Ran `tsc && vite build`: compiled cleanly in 3.95s.
- Created backend pytest suite: **103 passed, 0 failed** in 5.56s.
- Created frontend vitest suite: **2 passed, 0 failed**.
- Verified database persistence and end-to-end API communication.
