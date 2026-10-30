"""
Tests for Screenshot fixes:
1. Amount regex: must start with a digit. "Rs.," is not read as an amount.
2. 3-tier amount parsing: currency marker -> "read", label -> "read", misread rupee sign -> "low_confidence".
3. Verdict: never return clean_no_findings unless BOTH amount and status are "read".
   If either is missing and there are no findings, return Verdict.inconclusive with display label "Could not verify this screenshot".
4. Summary: must never print the word None. For inconclusive, say which of "the amount" / "the payment status" could not be read.
5. UTR format rule: labelled UTR / "UPI Ref" that is digits-only and not exactly 12 digits -> medium finding "UTR_FORMAT".
"""
from app.schemas.shared import Severity, Verdict
from app.services.screenshot_service import (
    _build_screenshot_summary,
    _check_screenshot_rules,
    _decide_screenshot_verdict,
    _extract_fields,
)


def test_amount_regex_does_not_match_lone_comma():
    # "Rs.," must NOT match as an amount
    fields = _extract_fields("Payment processed Rs., thanks")
    assert fields["amount"]["status"] != "read"
    assert fields["amount"]["value"] is None


def test_amount_tiers():
    # Tier 1: Currency marker followed by digit -> read
    f1 = _extract_fields("Paid ₹500.00 to merchant")
    assert f1["amount"]["status"] == "read"
    assert f1["amount"]["value"] == "500.00"

    f1b = _extract_fields("Paid Rs. 1,250 to merchant")
    assert f1b["amount"]["status"] == "read"
    assert f1b["amount"]["value"] == "1,250"

    # Tier 2: Label followed by digit -> read
    f2 = _extract_fields("Total Amount: 750.50")
    assert f2["amount"]["status"] == "read"
    assert f2["amount"]["value"] == "750.50"

    # Tier 3: Misread rupee sign (% T Z ?) -> low_confidence
    f3 = _extract_fields("Paid % 450 to merchant")
    assert f3["amount"]["status"] == "low_confidence"
    assert f3["amount"]["value"] == "450"


def test_verdict_requires_both_amount_and_status_read():
    # Only amount read, no status -> inconclusive
    fields_amount_only = {
        "amount": {"value": "500", "status": "read"},
        "status": {"value": None, "status": "not_found"},
    }
    v1 = _decide_screenshot_verdict([], fields_amount_only, ocr_confidence=0.9, ocr_available=True)
    assert v1 == Verdict.inconclusive

    # Only status read, no amount -> inconclusive
    fields_status_only = {
        "amount": {"value": None, "status": "not_found"},
        "status": {"value": "paid", "status": "read"},
    }
    v2 = _decide_screenshot_verdict([], fields_status_only, ocr_confidence=0.9, ocr_available=True)
    assert v2 == Verdict.inconclusive

    # Low-confidence amount (tier 3) + status read -> still inconclusive
    fields_low_amount = {
        "amount": {"value": "500", "status": "low_confidence"},
        "status": {"value": "paid", "status": "read"},
    }
    v3 = _decide_screenshot_verdict([], fields_low_amount, ocr_confidence=0.9, ocr_available=True)
    assert v3 == Verdict.inconclusive

    # Both read -> clean_no_findings
    fields_both = {
        "amount": {"value": "500", "status": "read"},
        "status": {"value": "paid", "status": "read"},
    }
    v4 = _decide_screenshot_verdict([], fields_both, ocr_confidence=0.9, ocr_available=True)
    assert v4 == Verdict.clean_no_findings


def test_screenshot_summary_never_prints_none():
    # When amount missing
    f_missing_amount = {
        "amount": {"value": None, "status": "not_found"},
        "status": {"value": "paid", "status": "read"},
    }
    sum1 = _build_screenshot_summary(Verdict.inconclusive, f_missing_amount, [])
    assert "None" not in sum1
    assert "the amount could not be read" in sum1

    # When status missing
    f_missing_status = {
        "amount": {"value": "500", "status": "read"},
        "status": {"value": None, "status": "not_found"},
    }
    sum2 = _build_screenshot_summary(Verdict.inconclusive, f_missing_status, [])
    assert "None" not in sum2
    assert "the payment status could not be read" in sum2

    # When both missing
    f_missing_both = {
        "amount": {"value": None, "status": "not_found"},
        "status": {"value": None, "status": "not_found"},
    }
    sum3 = _build_screenshot_summary(Verdict.inconclusive, f_missing_both, [])
    assert "None" not in sum3
    assert "both the amount and the payment status could not be read" in sum3

    # Clean summary should never say None
    f_clean = {
        "amount": {"value": "1500", "raw": "₹1500", "status": "read"},
        "status": {"value": "paid", "raw": "paid", "status": "read"},
    }
    sum4 = _build_screenshot_summary(Verdict.clean_no_findings, f_clean, [])
    assert "None" not in sum4


def test_utr_format_rule():
    fields = {"amount": {"status": "read"}, "status": {"status": "read"}}
    # 10 digits labelled UTR (invalid - should be 12)
    text_invalid_utr = "Payment Successful UPI Ref No: 1234567890 to merchant"
    ev = _check_screenshot_rules(fields, text_invalid_utr, ocr_confidence=0.9)
    utr_ev = [e for e in ev if e.category == "UTR_FORMAT"]
    assert len(utr_ev) == 1
    assert utr_ev[0].severity == Severity.medium

    # 12 digits labelled UTR (valid)
    text_valid_utr = "Payment Successful UPI Ref No: 123456789012 to merchant"
    ev2 = _check_screenshot_rules(fields, text_valid_utr, ocr_confidence=0.9)
    assert not any(e.category == "UTR_FORMAT" for e in ev2)
