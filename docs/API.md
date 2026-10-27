# PhishShield REST API Specification

Base URL: `http://127.0.0.1:8000/api`  
Content-Type: `application/json` (except file upload endpoints which use `multipart/form-data`)

---

## 1. Health & Readiness

### `GET /api/health`
Returns system status, database health, ML model readiness, OCR availability, and reputation intelligence sources.

**Response:**
```json
{
  "status": "ok",
  "db": "ok",
  "model_loaded": true,
  "model_version": "v1.0.0-20261010-hgb",
  "model_error": null,
  "ocr_available": false,
  "ocr_engine": null,
  "ocr_detail": "No OCR engine available. Install Tesseract or rapidocr-onnxruntime.",
  "external_lookups_enabled": false,
  "reputation_sources": {
    "google_safe_browsing": "unconfigured",
    "urlhaus": "unconfigured",
    "phishtank": "unconfigured",
    "openphish": "unconfigured"
  },
  "version": "1.0.0"
}
```

---

## 2. URL Threat Analysis

### `POST /api/url/analyze`
Submits a URL for static security analysis, brand lookalike verification, and machine learning assessment.

**Request Body:**
```json
{
  "url": "https://netbanking.hdfcbank.com/netbanking/"
}
```

**Response (200 OK):**
```json
{
  "investigation_id": "97d391aa-924b-4b13-a4c3-1c3905e71ea4",
  "type": "url",
  "created_at": "2026-10-10T05:50:00.000000Z",
  "verdict": "clean_no_findings",
  "display_label": "No known threat found",
  "summary": "No known threats were detected in this URL. This is not a guarantee of safety—always verify through official channels.",
  "evidence": [
    {
      "id": "...",
      "category": "MODEL_SCORE",
      "severity": "info",
      "title": "ML model assessment",
      "detail": "Model places this URL in the 'low' risk band.",
      "source": "model"
    }
  ],
  "checks_performed": [
    { "name": "URL parsing & normalisation", "status": "completed", "detail": "Valid HTTP/HTTPS structure." },
    { "name": "Domain brand lookalike checks", "status": "completed", "detail": "Official domain match." }
  ],
  "limitations": [
    "Analysis is based on URL structure, security rules, and optional threat-intelligence feeds only. It does not fetch or render the page.",
    "A clean result is NOT a guarantee of safety."
  ],
  "recommendations": [
    "Verify the URL independently before entering passwords or payment details."
  ],
  "analysis_version": "1.0.0",
  "model_version": "v1.0.0-20261010-hgb",
  "input_summary": "URL: netbanking.hdfcbank.com/netbanking/",
  "saved": true
}
```

---

## 3. Android APK Analysis

### `POST /api/apk/analyze`
Performs static inspection on uploaded APK binary archives.

- **Content-Type:** `multipart/form-data`
- **Form Key:** `file` (Binary APK archive, max 100 MB)

**Response:** Returns `AnalysisResult` with verdict (`Likely malicious`, `Suspicious app`, `No strong warning signs found`, or `Could not analyse`).

---

## 4. SMS & Sender Verification

### `POST /api/sms/analyze`
Verifies message content against urgency, KYC, financial lure patterns, and validates sender against registered Indian TRAI DLT alphanumeric headers.

**Request Body:**
```json
{
  "message": "Your OTP is 482910. Do not share this OTP with anyone.",
  "sender": "VK-HDFCBK"
}
```

**Response:** Returns `AnalysisResult` with verdict (`Likely scam`, `Suspicious message`, `No strong warning signs found`, or `Could not verify`).

---

## 5. Payment Screenshot OCR

### `POST /api/screenshot/analyze`
Extracts text from payment receipts (PNG, JPG, WEBP) and validates amount, transaction UTR consistency, and status.

- **Content-Type:** `multipart/form-data`
- **Form Key:** `file` (Image file, max 10 MB)

---

## 6. History & Dashboard

### `GET /api/history`
Query parameters:
- `type` (optional): `url`, `apk`, `sms`, `screenshot`
- `verdict` (optional): `malicious`, `suspicious`, `clean_no_findings`, `inconclusive`
- `q` (optional): search text in input summary
- `page` (default 1): integer
- `page_size` (default 20): integer

### `GET /api/history/{id}`
Returns full investigation record with raw `result_json`.

### `DELETE /api/history/{id}`
Deletes investigation record and cascading evidence from the database.

### `GET /api/history/{id}/export.pdf`
Streams an audit PDF report generated via ReportLab.

### `GET /api/dashboard/stats`
Returns total counts, counts by module type, counts by verdict, and 5 recent scans.

---

## 7. Error Format Envelope

All non-200 responses return structured JSON:
```json
{
  "detail": {
    "error": {
      "code": "INVALID_URL",
      "message": "URL exceeds maximum permitted length of 2048 characters."
    }
  }
}
```
