"""
Screenshot analysis service – OCR + consistency checks.
Never executes or renders images.
"""
from __future__ import annotations

import hashlib
import logging
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from app.config import get_settings
from app.schemas.shared import (
    AnalysisResult, CheckPerformed, CheckStatus, EvidenceItem, EvidenceSource,
    ModuleType, Severity, Verdict, make_display_label, standard_recommendations,
)

logger = logging.getLogger(__name__)

ALLOWED_MIME_TYPES = {"image/png", "image/jpeg", "image/webp"}
ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp"}
MAX_IMAGE_PIXELS = 144_000_000  # 12000 x 12000


def _detect_ocr_engine() -> tuple[Optional[str], str]:
    """Detect available OCR engine. Returns (engine_name, detail)."""
    # Try tesseract first
    try:
        import pytesseract
        settings = get_settings()
        if settings.TESSERACT_CMD:
            pytesseract.pytesseract.tesseract_cmd = settings.TESSERACT_CMD
        version = pytesseract.get_tesseract_version()
        return "tesseract", f"Tesseract {version}"
    except Exception as e:
        logger.debug(f"Tesseract not available: {e}")

    # Try rapidocr
    try:
        from rapidocr_onnxruntime import RapidOCR  # type: ignore
        return "rapidocr", "RapidOCR (ONNX)"
    except ImportError:
        pass

    # Try easyocr
    try:
        import easyocr  # type: ignore
        return "easyocr", "EasyOCR"
    except ImportError:
        pass

    return None, "No OCR engine available. Install Tesseract or rapidocr-onnxruntime."


_OCR_ENGINE: Optional[str] = None
_OCR_DETAIL: str = ""


def get_ocr_status() -> tuple[bool, str, str]:
    """Returns (available, engine_name, detail)."""
    global _OCR_ENGINE, _OCR_DETAIL
    if _OCR_ENGINE is None and _OCR_DETAIL == "":
        _OCR_ENGINE, _OCR_DETAIL = _detect_ocr_engine()
    available = _OCR_ENGINE is not None
    return available, _OCR_ENGINE or "", _OCR_DETAIL


_RAPID_OCR_INSTANCE = None


def _get_rapid_ocr():
    global _RAPID_OCR_INSTANCE
    if _RAPID_OCR_INSTANCE is None:
        from rapidocr_onnxruntime import RapidOCR
        _RAPID_OCR_INSTANCE = RapidOCR()
    return _RAPID_OCR_INSTANCE


def _perform_ocr(image_bytes: bytes, langs: str) -> tuple[str, float]:
    """Run OCR and return (text, confidence_0_to_1)."""
    get_ocr_status()

    if _OCR_ENGINE == "tesseract":
        import pytesseract
        from PIL import Image
        import io
        img = Image.open(io.BytesIO(image_bytes))
        # Get data with confidence
        data = pytesseract.image_to_data(img, lang=langs, output_type=pytesseract.Output.DICT)
        text = pytesseract.image_to_string(img, lang=langs)
        confs = [c for c in data.get("conf", []) if isinstance(c, (int, float)) and c >= 0]
        confidence = sum(confs) / len(confs) / 100 if confs else 0.0
        return text, confidence

    if _OCR_ENGINE == "rapidocr":
        from PIL import Image
        import io
        import numpy as np
        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        arr = np.array(img)
        ocr = _get_rapid_ocr()
        result, _ = ocr(arr)
        if result:
            texts = [str(item[1]) for item in result if len(item) > 1]
            scores = []
            for item in result:
                if len(item) > 2:
                    try:
                        scores.append(float(item[2]))
                    except (ValueError, TypeError):
                        pass
            confidence = sum(scores) / len(scores) if scores else 0.0
            return "\n".join(texts), confidence
        return "", 0.0

    if _OCR_ENGINE == "easyocr":
        import easyocr
        from PIL import Image
        import io
        import numpy as np
        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        arr = np.array(img)
        reader = easyocr.Reader(["en"], gpu=False, verbose=False)
        result = reader.readtext(arr)
        texts = [item[1] for item in result]
        scores = [item[2] for item in result]
        confidence = sum(scores) / len(scores) if scores else 0.0
        return "\n".join(texts), confidence

    return "", 0.0


def _preprocess_image(image_bytes: bytes) -> bytes:
    """Basic preprocessing: grayscale, upscale if small, denoise."""
    try:
        from PIL import Image, ImageFilter, ImageEnhance
        import io
        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        w, h = img.size
        # Upscale if too small
        if max(w, h) < 800:
            scale = 800 / max(w, h)
            img = img.resize((int(w * scale), int(h * scale)), Image.LANCZOS)
        # Convert to grayscale for OCR
        gray = img.convert("L")
        # Slight sharpening
        enhanced = ImageEnhance.Sharpness(gray).enhance(1.5)
        buf = io.BytesIO()
        enhanced.save(buf, format="PNG")
        return buf.getvalue()
    except Exception as e:
        logger.warning(f"Preprocessing failed: {e}")
        return image_bytes


def _extract_fields(text: str) -> dict:
    """Extract payment fields from OCR text."""
    fields = {}

    # Amount
    amount_match = re.search(
        r"(?:\u20b9|Rs\.?|INR)\s*([\d,]+(?:\.\d{1,2})?)",
        text, re.IGNORECASE
    )
    if amount_match:
        fields["amount"] = {"raw": amount_match.group(0), "value": amount_match.group(1), "status": "read"}
    else:
        fields["amount"] = {"raw": None, "value": None, "status": "not_found"}

    # Status
    status_pattern = re.compile(
        r"\b(success(?:ful)?|paid|completed?|failed?|pending|processing|declined?|initiated?|"
        r"safal|saphal)\b",
        re.IGNORECASE
    )
    status_match = status_pattern.search(text)
    if status_match:
        fields["status"] = {"raw": status_match.group(0), "value": status_match.group(0).lower(), "status": "read"}
    else:
        fields["status"] = {"raw": None, "value": None, "status": "not_found"}

    # UPI Transaction ID / UTR (12 digits typically)
    utr_match = re.search(r"\b(\d{12})\b", text)
    if utr_match:
        fields["utr"] = {"raw": utr_match.group(1), "value": utr_match.group(1), "status": "read"}
    else:
        # Try longer reference numbers
        ref_match = re.search(r"(?:UTR|Ref|Reference|Transaction\s*ID)[:\s]*([A-Z0-9]{8,20})", text, re.IGNORECASE)
        if ref_match:
            fields["utr"] = {"raw": ref_match.group(1), "value": ref_match.group(1), "status": "low_confidence"}
        else:
            fields["utr"] = {"raw": None, "value": None, "status": "not_found"}

    # UPI ID
    upi_match = re.search(r"[\w.\-]+@[\w]+", text)
    if upi_match:
        fields["upi_id"] = {"raw": upi_match.group(0), "value": upi_match.group(0), "status": "read"}
    else:
        fields["upi_id"] = {"raw": None, "value": None, "status": "not_found"}

    # Date
    date_match = re.search(
        r"\b(\d{1,2}[-/]\d{1,2}[-/]\d{2,4}|\d{4}[-/]\d{2}[-/]\d{2})\b", text
    )
    if date_match:
        fields["date"] = {"raw": date_match.group(0), "value": date_match.group(0), "status": "read"}
    else:
        fields["date"] = {"raw": None, "value": None, "status": "not_found"}

    return fields


KNOWN_PSP_HANDLES = {
    "oksbi", "okhdfcbank", "okaxis", "okicici", "ybl", "ibl", "abl",
    "paytm", "paytmbank", "icici", "axl", "kotak", "federal",
    "rbl", "indus", "sbi", "upi", "upirzp", "razorpay",
    "timecosmos", "barodampay", "cnrb", "kvb",
}


def _check_screenshot_rules(fields: dict, text: str, ocr_confidence: float) -> list[EvidenceItem]:
    evidence = []

    # Conflicting status words
    status_words = re.findall(
        r"\b(success|failed|pending|processing|completed|declined)\b",
        text, re.IGNORECASE
    )
    unique_statuses = set(s.lower() for s in status_words)
    if len(unique_statuses) > 1 and ("success" in unique_statuses or "successful" in unique_statuses):
        if any(s in unique_statuses for s in ("failed", "declined", "pending")):
            evidence.append(EvidenceItem(
                category="CONFLICTING_STATUS",
                severity=Severity.high,
                title="Conflicting payment status words detected",
                detail=f"Found contradictory status indicators: {', '.join(unique_statuses)}. "
                       "This may indicate a manipulated screenshot.",
                source=EvidenceSource.ocr,
            ))

    # Success without reference ID
    status_val = (fields.get("status") or {}).get("value", "")
    utr_status = (fields.get("utr") or {}).get("status", "not_found")
    if status_val in ("success", "successful", "paid", "completed") and utr_status == "not_found":
        evidence.append(EvidenceItem(
            category="SUCCESS_WITHOUT_REFERENCE",
            severity=Severity.medium,
            title="'Success' status without a transaction reference number",
            detail="A genuine payment confirmation usually includes a UTR/reference number. "
                   "The absence of one is unusual.",
            source=EvidenceSource.ocr,
        ))

    # UPI ID handle validation
    upi_val = (fields.get("upi_id") or {}).get("value")
    if upi_val and "@" in upi_val:
        handle = upi_val.split("@")[1].lower()
        if handle not in KNOWN_PSP_HANDLES:
            evidence.append(EvidenceItem(
                category="UNKNOWN_UPI_HANDLE",
                severity=Severity.low,
                title=f"Unrecognised UPI handle (@{handle})",
                detail=f"The UPI handle '@{handle}' is not in our list of known PSP handles. "
                       "This is informational only.",
                source=EvidenceSource.ocr,
            ))

    # Low OCR confidence
    if ocr_confidence < 0.5 and ocr_confidence > 0:
        evidence.append(EvidenceItem(
            category="LOW_OCR_CONFIDENCE",
            severity=Severity.info,
            title=f"Low OCR confidence ({ocr_confidence:.0%})",
            detail="Text extraction confidence is low. Results may contain errors. "
                   "Verify the details manually.",
            source=EvidenceSource.ocr,
        ))

    return evidence


def _decide_screenshot_verdict(
    evidence: list[EvidenceItem], fields: dict, ocr_confidence: float, ocr_available: bool
) -> Verdict:
    if not ocr_available:
        return Verdict.inconclusive

    # Check if key fields were read
    key_read = sum(
        1 for k in ("amount", "status") if (fields.get(k) or {}).get("status") == "read"
    )

    if ocr_confidence < 0.3 and ocr_confidence > 0 and key_read == 0:
        return Verdict.inconclusive  # Important details could not be read

    high = sum(1 for e in evidence if e.severity == Severity.high)
    medium = sum(1 for e in evidence if e.severity == Severity.medium)

    if high >= 1 or medium >= 2:
        return Verdict.malicious

    if medium >= 1:
        return Verdict.suspicious

    if key_read == 0:
        # Return a special variant of inconclusive for "important details not read"
        return Verdict.inconclusive

    return Verdict.clean_no_findings


class ScreenshotAnalysisService:
    def __init__(self):
        self.settings = get_settings()

    async def analyse(self, data: bytes, filename: str = "screenshot.png") -> tuple[AnalysisResult, Optional[dict]]:
        import time
        t_start = time.perf_counter()
        investigation_id = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc).isoformat()
        checks: list[CheckPerformed] = []
        limitations = [
            "A screenshot cannot prove that money was received. Always verify in your bank or UPI app.",
            "Screenshot forgery detection (ELA, clone detection) is not implemented. Inconsistencies in text/numbers are checked only.",
            "OCR accuracy depends on image quality. Low-quality images may produce incorrect field values.",
            "UTR/reference number format validation is approximate. Verify with your bank.",
        ]

        # OCR availability check
        ocr_available, ocr_engine, ocr_detail = get_ocr_status()
        if not ocr_available:
            result = AnalysisResult(
                investigation_id=investigation_id, type=ModuleType.screenshot, created_at=created_at,
                verdict=Verdict.inconclusive, display_label=make_display_label("screenshot", Verdict.inconclusive),
                summary=f"OCR engine not available: {ocr_detail}. Screenshot analysis is not possible.",
                checks_performed=[CheckPerformed(name="OCR engine", status=CheckStatus.unavailable,
                                                  detail=ocr_detail)],
                limitations=limitations, recommendations=standard_recommendations(Verdict.inconclusive),
            )
            return result, None

        checks.append(CheckPerformed(name="OCR engine", status=CheckStatus.completed, detail=ocr_detail))

        # File size check
        if len(data) > self.settings.max_image_bytes:
            verdict = Verdict.inconclusive
            result = AnalysisResult(
                investigation_id=investigation_id, type=ModuleType.screenshot, created_at=created_at,
                verdict=verdict, display_label=make_display_label("screenshot", verdict),
                summary=f"Image exceeds {self.settings.MAX_IMAGE_MB} MB limit.",
                checks_performed=[CheckPerformed(name="File size", status=CheckStatus.failed,
                                                  detail="Exceeds limit.")],
                limitations=limitations, recommendations=standard_recommendations(verdict),
            )
            return result, None

        # Image validation via Pillow
        try:
            from PIL import Image
            import io
            Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS
            img = Image.open(io.BytesIO(data))
            img.verify()
            img = Image.open(io.BytesIO(data))
            w, h = img.size
            checks.append(CheckPerformed(
                name="Image validation", status=CheckStatus.completed,
                detail=f"Valid image: {w}x{h} px, format: {img.format}"
            ))
            if max(w, h) > 12000:
                raise ValueError(f"Image dimensions too large: {w}x{h}")
        except Exception as e:
            result = AnalysisResult(
                investigation_id=investigation_id, type=ModuleType.screenshot, created_at=created_at,
                verdict=Verdict.inconclusive, display_label=make_display_label("screenshot", Verdict.inconclusive),
                summary=f"Could not open image: {e}",
                checks_performed=[CheckPerformed(name="Image validation", status=CheckStatus.failed,
                                                  detail=str(e))],
                limitations=limitations, recommendations=standard_recommendations(Verdict.inconclusive),
            )
            return result, None

        # Hash
        file_hash = hashlib.sha256(data).hexdigest()

        # Preprocess + OCR
        try:
            preprocessed = _preprocess_image(data)
            checks.append(CheckPerformed(name="Image preprocessing", status=CheckStatus.completed,
                                          detail="Grayscale and sharpening applied."))
        except Exception as e:
            preprocessed = data
            checks.append(CheckPerformed(name="Image preprocessing", status=CheckStatus.failed,
                                          detail=str(e)))

        try:
            langs = self.settings.OCR_LANGS
            ocr_text, ocr_confidence = _perform_ocr(preprocessed, langs)
            checks.append(CheckPerformed(
                name="OCR text extraction", status=CheckStatus.completed,
                detail=f"Extracted {len(ocr_text)} chars, confidence: {ocr_confidence:.0%}"
            ))
        except Exception as e:
            logger.error(f"OCR failed: {e}")
            result = AnalysisResult(
                investigation_id=investigation_id, type=ModuleType.screenshot, created_at=created_at,
                verdict=Verdict.inconclusive, display_label=make_display_label("screenshot", Verdict.inconclusive),
                summary=f"OCR extraction failed: {e}",
                checks_performed=checks + [CheckPerformed(name="OCR text extraction",
                                                          status=CheckStatus.failed, detail=str(e))],
                limitations=limitations, recommendations=standard_recommendations(Verdict.inconclusive),
            )
            return result, None

        # Field extraction
        fields = _extract_fields(ocr_text)
        checks.append(CheckPerformed(
            name="Field extraction", status=CheckStatus.completed,
            detail=f"Fields found: {', '.join(k for k, v in fields.items() if v.get('status') == 'read')}"
        ))

        # Consistency checks
        evidence = _check_screenshot_rules(fields, ocr_text, ocr_confidence)
        checks.append(CheckPerformed(name="Consistency checks", status=CheckStatus.completed,
                                      detail=f"{len(evidence)} findings."))

        verdict = _decide_screenshot_verdict(evidence, fields, ocr_confidence, ocr_available)

        # Special label for "important details not read"
        if verdict == Verdict.inconclusive:
            key_read = sum(1 for k in ("amount", "status") if (fields.get(k) or {}).get("status") == "read")
            if key_read == 0 and ocr_confidence > 0:
                display_label = "Important details could not be read"
            else:
                display_label = make_display_label("screenshot", verdict)
        else:
            display_label = make_display_label("screenshot", verdict)

        summary = _build_screenshot_summary(verdict, fields, evidence)
        recommendations = standard_recommendations(verdict)
        recommendations.insert(0,
            "A screenshot is NOT proof of payment. Always confirm receipt in your official bank or UPI app."
        )

        result = AnalysisResult(
            investigation_id=investigation_id, type=ModuleType.screenshot, created_at=created_at,
            verdict=verdict, display_label=display_label, summary=summary,
            evidence=evidence, checks_performed=checks,
            limitations=limitations, recommendations=recommendations,
            analysis_version="1.0.0",
            input_summary=f"Image ({len(data) // 1024} KB)",
        )

        screenshot_details = {
            "file_hash": file_hash,
            "file_size_bytes": len(data),
            "image_width": w,
            "image_height": h,
            "ocr_engine": ocr_engine,
            "ocr_confidence": ocr_confidence,
            "extracted_fields": fields,
        }

        return result, screenshot_details


def _build_screenshot_summary(verdict: Verdict, fields: dict, evidence: list) -> str:
    if verdict == Verdict.malicious:
        high_ev = [e for e in evidence if e.severity == Severity.high]
        reason = high_ev[0].title if high_ev else "inconsistent data"
        return f"Suspicious or inconsistent evidence detected: {reason}. Do not accept this as proof of payment."
    if verdict == Verdict.suspicious:
        return "Some inconsistencies were found in this screenshot. Verify payment through official channels."
    if verdict == Verdict.inconclusive:
        return ("Important payment details could not be clearly read from this image. "
                "The image may be blurry, cropped, or not a payment screenshot.")
    amount = (fields.get("amount") or {}).get("raw", "unknown amount")
    status = (fields.get("status") or {}).get("value", "unknown status")
    return (f"No obvious inconsistencies detected ({status}, {amount}). "
            "Always verify receipt in your own bank or UPI app — a screenshot alone is not proof.")
