"""
Tests for SMS improvements: shorthand expansion, sender splitting, KYC patterns,
wrong-payment and law-enforcement scam rules, verdict logic, and ML model integration.
"""
import asyncio
from unittest.mock import patch

from app.schemas.shared import Severity, Verdict
from app.services.sms_ml import predict_sms
from app.services.sms_service import SmsAnalysisService, verify_sender
from app.services.sms_text import expand_shorthand, normalise_for_model, split_sender


def test_expand_shorthand():
    text = "Pls updt ur a/c k y c immediately. Ur acc blkd due to adhar txn issue. Plz u do it."
    expanded = expand_shorthand(text)
    assert "please" in expanded.lower()
    assert "update" in expanded.lower()
    assert "your" in expanded.lower()
    assert "account" in expanded.lower()
    assert "kyc" in expanded.lower()
    assert "blocked" in expanded.lower()
    assert "aadhaar" in expanded.lower()
    assert "transaction" in expanded.lower()
    assert "you" in expanded.lower()


def test_split_sender():
    assert split_sender("VK-SBIINB") == "SBIINB"
    assert split_sender("vk SBIINB") == "SBIINB"
    assert split_sender("SBIINB") == "SBIINB"
    assert split_sender("VKHDFCBK") == "HDFCBK"
    assert split_sender("ad_AXISBK") == "AXISBK"
    assert split_sender("  cp - paytm  ") == "PAYTM"


def test_verify_sender_with_glued_and_spaced_headers():
    r1 = verify_sender("VK-SBIINB")
    assert r1["state"] == "exact_match"
    assert "SBI" in r1["brand"]

    r2 = verify_sender("vk SBIINB")
    assert r2["state"] == "exact_match"
    assert "SBI" in r2["brand"]

    r3 = verify_sender("VKHDFCBK")
    assert r3["state"] == "exact_match"
    assert "HDFC" in r3["brand"]


def test_update_ur_kyc_vk_srink_not_clean():
    service = SmsAnalysisService()
    result, _ = asyncio.run(service.analyse("UPDATE UR KYC", sender="vk SRINK"))
    assert result.verdict in (Verdict.suspicious, Verdict.malicious)
    assert any("KYC" in e.category or "KYC" in e.title for e in result.evidence)


def test_broadened_kyc_patterns():
    service = SmsAnalysisService()
    phrases = [
        "Dear customer, please complete your kyc today to avoid suspension.",
        "Link your aadhaar card immediately.",
        "Verify ur PAN number now.",
        "Your account kyc has expired, please renew immediately.",
        "KYC is required for continued banking services.",
        "Your account KYC is not updated. Visit link to submit your kyc.",
    ]
    for msg in phrases:
        result, _ = asyncio.run(service.analyse(msg, sender="VK-SBIINB"))
        has_kyc_evidence = any("KYC" in e.category or "KYC" in e.title for e in result.evidence)
        assert has_kyc_evidence, f"Failed to detect KYC in: {msg}"


def test_wrong_payment_scam_rule():
    service = SmsAnalysisService()
    msg = "I have paid Rs 5000 by mistake to your UPI, please send it back immediately to 9876543210@upi."
    result, _ = asyncio.run(service.analyse(msg, sender=None))
    assert result.verdict in (Verdict.suspicious, Verdict.malicious)
    assert any(e.category == "WRONG_PAYMENT_SCAM" for e in result.evidence)


def test_law_enforcement_digital_arrest_scam_rule():
    service = SmsAnalysisService()
    msg = "You are placed under digital arrest by CBI officer for illegal money laundering parcel in customs."
    result, _ = asyncio.run(service.analyse(msg, sender=None))
    assert result.verdict in (Verdict.suspicious, Verdict.malicious)
    assert any(e.category == "LAW_ENFORCEMENT_IMPERSONATION" for e in result.evidence)


def test_verdict_logic_unverified_sender_harmless_text_is_inconclusive():
    service = SmsAnalysisService()
    # Harmless text without verified DLT and without OTP warning
    msg = "Hello team, let us meet tomorrow afternoon at 3 PM in the conference room."
    result, _ = asyncio.run(service.analyse(msg, sender="XYZCORP"))
    assert result.verdict == Verdict.inconclusive
    assert result.display_label == "Not enough evidence"
    assert "not proof of safety" in result.summary.lower() or "not enough evidence" in result.summary.lower()


def test_verdict_logic_verified_dlt_sender_clean_no_findings():
    service = SmsAnalysisService()
    # Verified SBI sender with benign balance alert
    msg = "Dear customer, your request for account statement has been processed."
    result, _ = asyncio.run(service.analyse(msg, sender="VK-SBIINB"))
    assert result.verdict == Verdict.clean_no_findings
    assert "not proof of safety" in result.summary.lower()


def test_verdict_logic_otp_warning_clean_no_findings():
    service = SmsAnalysisService()
    # Unverified sender but standard bank OTP security warning present
    msg = "Your OTP is 492018. Do not share your OTP with anyone, including bank officials."
    result, _ = asyncio.run(service.analyse(msg, sender="AUTHMSG"))
    assert result.verdict == Verdict.clean_no_findings


def test_sms_ml_prediction_sensible_probabilities():
    scam_msg = "URGENT: Your SBI account is blocked. Update ur KYC immediately at https://sbi-kyc-verify.net to restore access."
    pred_scam = predict_sms(scam_msg)
    assert pred_scam["available"] is True
    assert pred_scam["scam_probability"] > 0.5

    genuine_msg = "Dear SBI User, your OTP for transaction of INR 1,200.00 is 849201. Valid for 10 mins. Do NOT share with anyone."
    pred_gen = predict_sms(genuine_msg)
    assert pred_gen["available"] is True
    assert pred_gen["scam_probability"] < 0.6


def test_sms_ml_robustness_to_shorthand_and_uppercase():
    msg1 = "UPDATE UR KYC NOW ACC BLKD PLS VISIT"
    pred1 = predict_sms(msg1)
    assert pred1["available"] is True

    msg2 = normalise_for_model(msg1)
    assert "your" in msg2
    assert "account" in msg2
    assert "blocked" in msg2


def test_sms_ml_model_unavailable_fallback():
    # Test that predict_sms never raises even when model load fails
    with patch("app.services.sms_ml.get_model", return_value=None):
        pred = predict_sms("Any message")
        assert pred["available"] is False
        assert pred["scam_probability"] == 0.0

    # Ensure SMS service still works without ML
    with patch("app.services.sms_ml.predict_sms", return_value={"available": False, "scam_probability": 0.0, "band": "low"}):
        service = SmsAnalysisService()
        result, _ = asyncio.run(service.analyse("Simple message", sender="VK-SBIINB"))
        assert result is not None
        assert result.verdict is not None


def test_sms_ml_alone_never_causes_malicious_verdict():
    # If ML probability is >= 0.85, it only adds medium severity evidence
    with patch("app.services.sms_ml.predict_sms", return_value={
        "available": True,
        "scam_probability": 0.95,
        "band": "high",
        "model_version": "test-v1",
    }):
        service = SmsAnalysisService()
        # Message with no regex rules triggered
        msg = "We have an important announcement regarding our upcoming community event next week."
        result, _ = asyncio.run(service.analyse(msg, sender="VK-SBIINB"))
        # Must NOT be malicious because ML alone adds at most medium severity
        assert result.verdict != Verdict.malicious
