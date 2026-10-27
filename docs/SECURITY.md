# PhishShield Security & Privacy Policy

Verified: **October 10, 2026**

---

## 1. Prime Security Guarantees

1. **No Target URL Visiting:** The backend **never fetches, opens, renders, or downloads** content from a user-submitted URL. This prevents IP deanonymization, SSRF attacks, browser exploitation, and triggering one-time phishing tokens.
2. **No Untrusted Execution:** Uploaded Android APKs and screenshots are **never executed, installed, or emulated**. Analysis is strictly static (AXML/DEX header parsing, OCR parsing).
3. **Zip Bomb Defense:** APK uploads are inspected in memory for decompression ratios (`> 100x`), maximum entries (`> 1000`), and maximum uncompressed volume (`> 500 MB`). Malicious archives are rejected before processing.
4. **Denial-of-Service Defense:**
   - URL inputs are capped at 2,048 characters.
   - APK uploads are capped at 100 MB (`MAX_APK_MB`).
   - Image uploads are capped at 10 MB (`MAX_IMAGE_MB`) and dimensions capped at 12,000x12,000 px via Pillow decomp-bomb guards (`MAX_IMAGE_PIXELS`).
   - Rate limiting enabled via SlowAPI.

---

## 2. Privacy & Data Handling

1. **Privacy-by-Default:** `ENABLE_EXTERNAL_LOOKUPS=false` in `.env.example`. When disabled, no user input is ever forwarded to third-party APIs.
2. **Local Reputation Matching:** The platform caches hashes of public feeds (URLhaus, OpenPhish) in SQLite so lookups occur entirely offline.
3. **Credential Masking:**
   - 6-digit OTPs are redacted (`[REDACTED-OTP]`).
   - 12-digit Aadhaar numbers are redacted (`[REDACTED-AADHAAR]`).
   - 16-digit credit/debit card numbers are redacted (`[REDACTED-CARD]`).
   - Mobile numbers are masked (`[REDACTED-PHONE]`).
   - `STORE_FULL_SMS_TEXT=false` by default.
4. **Ephemeral Uploads:** `RETAIN_UPLOADS=false` by default; uploaded files are not stored on disk after scan completion.

---

## 3. Web Application Security Headers

FastAPI enforces the following headers on all responses:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`
