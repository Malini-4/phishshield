# PhishShield Honest Limitations & Caveats

In accordance with Section 0.2 of the project specification, this document lists all known technical limitations of the system.

---

## 1. URL Threat Analysis Limitations

1. **No Content / DOM Inspection:** Analysis is static and lexical only. We do not fetch HTML, JavaScript, or network certificates. A clean domain hosting newly created phishing forms that contains zero deceptive lexical tokens may score as low risk.
2. **Shortened URLs:** Services like `bit.ly` or `tinyurl.com` obscure the destination host. PhishShield identifies that a shortener is used and flags it, but cannot follow redirects without visiting the target (which is prohibited for safety).
3. **No Domain Age Lookup:** WHOIS lookups are not performed to preserve investigator privacy and avoid rate limits. Domain registration age is therefore not evaluated.
4. **Curated Brand Coverage:** Brand impersonation relies on `data/reference/brand_domains.csv`. Unlisted regional brands will not trigger brand-specific lookalike checks (though generic ML risk bands still apply).

---

## 2. Android APK Analysis Limitations

1. **No Dynamic / Runtime Analysis:** Static inspection cannot detect runtime behavior, packed or encrypted payloads, dynamically downloaded DEX payloads (`DexClassLoader`), or reflective method calls.
2. **Official Package List is Finite:** The official package whitelist contains primary banking and payment apps. Unlisted legitimate apps may trigger warnings if they request sensitive permissions.

---

## 3. SMS & Sender Verification Limitations

1. **Header Spoofing:** A verified DLT alphanumeric header (e.g. `HDFCBK`) increases confidence, but does not offer absolute cryptographic proof due to SMS threading and cellular spoofing attacks.
2. **Regional Indian Languages:** English and Hinglish patterns are thoroughly supported. Devanagari and other Indian scripts have basic coverage based on keyword lists.

---

## 4. Payment Screenshot OCR Limitations

1. **No Cryptographic Payment Verification:** A screenshot is an image, not a blockchain or banking receipt. Anyone can forge a screenshot using online mock generators. Users are always instructed to verify funds in their bank app.
2. **OCR Engine Dependencies:** High-accuracy OCR requires Tesseract (`tesseract-ocr`) with language packs installed on the system. In environments without Tesseract, screenshot analysis will gracefully report that the OCR engine is unavailable.
3. **Visual Forgery (ELA / Clone Tool Detection):** Image manipulation detection (such as Error Level Analysis) is not implemented; analysis is restricted to text and numerical consistency.
