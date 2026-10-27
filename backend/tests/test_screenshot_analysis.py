"""
Unit tests for Payment Screenshot Investigation module.
Generates synthetic test images with Pillow to verify field extraction, OCR fallback, and consistency rules.
"""
import io
import pytest
from PIL import Image, ImageDraw
from app.services.screenshot_service import (
    ScreenshotAnalysisService,
    _extract_fields,
    _check_screenshot_rules,
    _decide_screenshot_verdict,
)
from app.schemas.shared import Verdict


@pytest.fixture
def service():
    return ScreenshotAnalysisService()


def create_synthetic_image(text_lines: list[str], width: int = 400, height: int = 300) -> bytes:
    """Create a synthetic PNG image with text drawn via Pillow."""
    img = Image.new("RGB", (width, height), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    y = 20
    for line in text_lines:
        draw.text((20, y), line, fill=(0, 0, 0))
        y += 35
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def test_field_extraction_logic():
    ocr_sample = """
    Payment Successful
    Paid to Ramesh Kumar
    UPI ID: ramesh@okhdfcbank
    Amount: ₹ 1,500.00
    UPI Ref: 412345678901
    Date: 12-10-2026
    """
    fields = _extract_fields(ocr_sample)
    assert fields["amount"]["status"] == "read"
    assert "1,500" in fields["amount"]["value"]
    assert fields["status"]["status"] == "read"
    assert "success" in fields["status"]["value"]
    assert fields["utr"]["status"] == "read"
    assert fields["utr"]["value"] == "412345678901"
    assert fields["upi_id"]["status"] == "read"
    assert fields["upi_id"]["value"] == "ramesh@okhdfcbank"


def test_rule_conflicting_status_detected():
    text = "Payment Status: Success! (Error: Transaction Failed, please retry)"
    fields = _extract_fields(text)
    evidence = _check_screenshot_rules(fields, text, ocr_confidence=0.9)
    assert any(e.category == "CONFLICTING_STATUS" for e in evidence)


def test_rule_success_without_reference():
    text = "Payment Successful. Amount: Rs 500. Thank you for your payment."
    fields = _extract_fields(text)
    evidence = _check_screenshot_rules(fields, text, ocr_confidence=0.85)
    assert any(e.category == "SUCCESS_WITHOUT_REFERENCE" for e in evidence)


def test_verdict_decision_when_inconsistent():
    text = "Payment Successful and Failed"
    fields = _extract_fields(text)
    evidence = _check_screenshot_rules(fields, text, ocr_confidence=0.9)
    verdict = _decide_screenshot_verdict(evidence, fields, ocr_confidence=0.9, ocr_available=True)
    assert verdict in (Verdict.malicious, Verdict.suspicious)


@pytest.mark.asyncio
async def test_invalid_image_rejected(service):
    corrupt_data = b"not an image file at all"
    res, details = await service.analyse(corrupt_data, "bad.png")
    assert res.verdict == Verdict.inconclusive
    assert "Could not open" in res.summary or "OCR engine not available" in res.summary


@pytest.mark.asyncio
async def test_oversized_dimensions_rejected(service):
    # Image.MAX_IMAGE_PIXELS guard
    oversized = Image.new("RGB", (13000, 100), color=(255, 255, 255))
    buf = io.BytesIO()
    oversized.save(buf, format="PNG")
    res, _ = await service.analyse(buf.getvalue(), "huge.png")
    assert res.verdict == Verdict.inconclusive
