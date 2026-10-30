# PhishShield 🛡️

**Evidence-Based Phishing, Scam & Digital Forensics Investigation Platform**

PhishShield is a web application designed to investigate suspicious links, malicious Android apps, fraud SMS messages, and fake payment receipts. Built with strict safety controls, it provides forensic analysis without executing untrusted code or visiting malicious websites.

---

## 🚀 Features & Modules

PhishShield consists of **6 core modules**:

1. **URL Threat Analysis:** High-accuracy lexical parser, lookalike brand detector, and calibrated ML classifier for detecting phishing links, credential stealers, and tunnel phishing without fetching target web pages.
2. **Android APK Static Analysis:** Decompiles and inspects Android archives (`.apk`) offline to catch banking trojan patterns (SMS intercept + boot + screen overlay), debug flags, and malicious C2 endpoints without running the app.
3. **SMS & Sender-Header Verification:** Distinguishes genuine bank OTP alerts from credential theft, KYC extortion, and utility scams. Features shorthand expansion, Hinglish scam detection, an offline ML scam language model, and DLT header parsing.
4. **Payment Screenshot Investigation (OCR):** Extracts text from UPI confirmation receipts (GPay, PhonePe, Paytm, BHIM) to uncover forged amounts, conflicting transaction statuses, and missing or invalid 12-digit UTR numbers.
5. **Connected Case Dossiers & Audit Ledger:** Groups related investigations via shared indicators (UPI IDs, phone numbers, suspect URLs) into tamper-evident cases with SHA-256 hash chaining and HMAC signing compliant with Section 63 BSA 2023.
6. **Investigation Reports & Audit History:** SQLite database with Write-Ahead Logging (WAL) and Alembic migrations. Includes dashboard analytics, interactive threat correlation graphs, and downloadable PDF legal export reports generated via ReportLab.

---

## 📋 Prerequisites

- **Python 3.10+** (Tested and verified on Python 3.14.0)
- **Node.js 18+** & **npm** (Tested on Node v24.14.0, npm 11.9.0)
- *(Optional)* Tesseract OCR binary for enhanced screenshot text extraction.

---

## ⚡ Quick Start Instructions

### 1. Start the Backend API Server

Open a terminal in the project directory (`phishshield`):

```powershell
$env:PYTHONPATH="backend"
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

The backend API will start at: `http://127.0.0.1:8000`  
Interactive Swagger docs: `http://127.0.0.1:8000/api/docs`  
Health check endpoint: `http://127.0.0.1:8000/api/health`

### 2. Start the Frontend Application

Open a second terminal in the project directory:

```powershell
cd frontend
npm run dev
```

Open your browser and navigate to:
👉 **`http://localhost:5173`** (or `http://127.0.0.1:5173`)

---

## 🧪 Running Automated Tests

All tests are real and run against the actual application code.

### Backend Tests (138 Tests)
```powershell
$env:PYTHONPATH="backend"
pytest backend/tests -v
```

### Frontend Tests & Type Checking
```powershell
cd frontend
npm test        # Runs Vitest unit tests
npm run build   # Type checks with tsc and builds production bundle
```

---

## 🤖 Retraining the ML Model

The production model is pre-trained and saved at `models/url_model.joblib`. To re-download threat feeds and retrain the model from scratch:

```powershell
cd phishshield
.\backend\.venv\Scripts\python ml\prepare_datasets.py
.\backend\.venv\Scripts\python ml\compare_models.py
.\backend\.venv\Scripts\python ml\train_url_model.py
.\backend\.venv\Scripts\python ml\evaluate_url_model.py
```

Evaluation metrics will be saved to `reports/url_model_metrics.json` and documented in `docs/MODEL_EVALUATION.md`.

---

## 🔒 Safety & Privacy Principles

1. **Zero URL Execution:** PhishShield never opens, visits, or executes user-submitted URLs.
2. **Zero APK Execution:** APK files are analyzed purely through static file inspection and are never installed or run.
3. **Privacy Redaction:** Sensitive details in SMS (6-digit OTPs, card numbers, Aadhaar numbers) are automatically masked before saving.
4. **No Fake Numbers:** Empty database → clean empty states. No hardcoded or faked statistics.

---

## 📖 Documentation

- [Architecture Guide](docs/ARCHITECTURE.md)
- [REST API Specification](docs/API.md)
- [Model Evaluation Report](docs/MODEL_EVALUATION.md)
- [Datasets & Provenance](docs/DATASETS.md)
- [Database & Migrations](docs/DATABASE.md)
- [Security & Privacy](docs/SECURITY.md)
- [Testing Verification](docs/TESTING.md)
- [Known Limitations](docs/LIMITATIONS.md)
- [Build Log](docs/BUILD_LOG.md)
