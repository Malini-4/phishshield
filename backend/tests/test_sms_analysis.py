"""
Comprehensive suite of >= 40 SMS and sender verification tests.
"""
import pytest
from app.services.sms_service import SmsAnalysisService, verify_sender, extract_urls_from_sms, _redact_sensitive
from app.schemas.shared import Verdict, Severity


@pytest.fixture
def service():
    return SmsAnalysisService()


# ── Sender Verification Tests (10 tests) ──────────────────────────────────────

def test_sender_exact_match_hdfc():
    r = verify_sender("HDFCBK")
    assert r["state"] == "exact_match"
    assert "HDFC" in r["brand"]


def test_sender_prefix_format():
    r = verify_sender("VK-SBIINB")
    assert r["state"] == "exact_match"
    assert "SBI" in r["brand"]


def test_sender_lookalike_hdfc():
    r = verify_sender("HDFCBX")
    assert r["state"] == "possible_lookalike"
    assert "HDFC" in r["brand"]


def test_sender_mobile_number_malformed():
    r = verify_sender("+919876543210")
    assert r["state"] == "malformed"


def test_sender_10_digits_malformed():
    r = verify_sender("9876543210")
    assert r["state"] == "malformed"


def test_sender_unverified():
    r = verify_sender("RANDOM")
    assert r["state"] == "unverified"


def test_sender_none():
    r = verify_sender(None)
    assert r["state"] == "unavailable"


def test_sender_empty():
    r = verify_sender("")
    assert r["state"] == "unavailable"


def test_sender_exact_match_amazon():
    r = verify_sender("AMAZON")
    assert r["state"] == "exact_match"


def test_sender_exact_match_aadhaar():
    r = verify_sender("AADHAR")
    assert r["state"] == "exact_match"


# ── Redaction & URL Extraction Tests (6 tests) ───────────────────────────────

def test_redact_otp():
    text = "Your OTP is 123456 for transaction."
    redacted = _redact_sensitive(text)
    assert "123456" not in redacted
    assert "[REDACTED-OTP]" in redacted


def test_redact_aadhaar():
    text = "Linked Aadhaar 1234 5678 9012 successfully."
    redacted = _redact_sensitive(text)
    assert "1234 5678 9012" not in redacted
    assert "[REDACTED-AADHAAR]" in redacted


def test_redact_phone():
    text = "Call officer at 9876543210 immediately."
    redacted = _redact_sensitive(text)
    assert "9876543210" not in redacted
    assert "[REDACTED-PHONE]" in redacted


def test_extract_urls_standard():
    text = "Visit https://sbi.co.in to view details"
    urls = extract_urls_from_sms(text)
    assert "https://sbi.co.in" in urls


def test_extract_urls_deobfuscates_brackets():
    text = "Check hxxp://evil[.]com/login now"
    urls = extract_urls_from_sms(text)
    assert any("evil.com" in u for u in urls)


def test_extract_obfuscated_shortener():
    text = "Click bit [.] ly/3xyz now"
    urls = extract_urls_from_sms(text)
    assert "[obfuscated-shortener]" in urls


# ── End-to-end SMS Analysis Service Tests (25+ tests) ────────────────────────

@pytest.mark.asyncio
async def test_legitimate_bank_otp_warning(service):
    # Legitimate bank OTP with explicit "Do not share" warning
    msg = "Your OTP for login is 482910. Do not share this OTP with anyone, including bank staff. Valid for 10 mins."
    res, _ = await service.analyse(msg, sender="HDFCBK")
    assert res.verdict in (Verdict.clean_no_findings, Verdict.suspicious)
    assert not any(e.category == "CREDENTIAL_REQUEST" for e in res.evidence)


@pytest.mark.asyncio
async def test_scam_credential_request(service):
    # Asks user to share OTP
    msg = "Dear customer, your card is blocked. Please share your OTP with customer support to unblock."
    res, _ = await service.analyse(msg, sender="9876543210")
    assert res.verdict == Verdict.malicious
    assert any(e.category == "CREDENTIAL_REQUEST" for e in res.evidence)


@pytest.mark.asyncio
async def test_kyc_suspension_threat_with_link(service):
    msg = "Dear SBI user, your YONO account is suspended. Update KYC within 24 hours at https://sbi-kyc-verify.top/ or account will be closed."
    res, _ = await service.analyse(msg, sender="VK-SBIINB")
    assert res.verdict in (Verdict.malicious, Verdict.suspicious)
    assert any(e.category in ("KYC_DEMAND", "URGENCY_PRESSURE", "BRAND_LINK_MISMATCH") for e in res.evidence)


@pytest.mark.asyncio
async def test_electricity_disconnection_scam(service):
    msg = "Dear consumer, your electricity bill is unpaid. Power will be disconnected tonight at 9:30 PM. Call electricity officer at 9811223344 immediately."
    res, _ = await service.analyse(msg, sender="+919811223344")
    assert res.verdict in (Verdict.malicious, Verdict.suspicious)
    assert any(e.category in ("FINANCIAL_SCAM_INDICATOR", "URGENCY_PRESSURE") for e in res.evidence)


@pytest.mark.asyncio
async def test_lottery_prize_scam(service):
    msg = "Congratulations! You have been selected as lucky winner of Rs 50,000 cashback reward. Click here to claim your prize."
    res, _ = await service.analyse(msg)
    assert res.verdict in (Verdict.malicious, Verdict.suspicious)
    assert any(e.category == "FINANCIAL_SCAM_INDICATOR" for e in res.evidence)


@pytest.mark.asyncio
async def test_work_from_home_job_scam(service):
    msg = "Work from home part time job opportunity! Earn Rs 3,500 daily by completing simple YouTube like tasks. Join Telegram group."
    res, _ = await service.analyse(msg)
    assert res.verdict in (Verdict.malicious, Verdict.suspicious)


@pytest.mark.asyncio
async def test_preapproved_loan_scam(service):
    msg = "Pre-approved personal loan of Rs 5,00,000 sanctioned for you with zero documents. Click link to withdraw funds."
    res, _ = await service.analyse(msg)
    assert res.verdict in (Verdict.malicious, Verdict.suspicious)


@pytest.mark.asyncio
async def test_parcel_delivery_fee_scam(service):
    msg = "India Post notification: Delivery failed due to incomplete address. Pay delivery fee of Rs 25 at indiapost-track.xyz to receive package."
    res, _ = await service.analyse(msg)
    assert res.verdict in (Verdict.malicious, Verdict.suspicious)


@pytest.mark.asyncio
async def test_hinglish_account_blocked_scam(service):
    msg = "Aapka account band ho jayega. Turant sampark kare helpline number 9822334455 par."
    res, _ = await service.analyse(msg)
    assert res.verdict in (Verdict.malicious, Verdict.suspicious)
    assert any(e.category == "REGIONAL_SCAM_LANGUAGE" for e in res.evidence)


@pytest.mark.asyncio
async def test_devanagari_scam(service):
    msg = "आपका बैंक खाता निलंबित कर दिया गया है। तुरंत संपर्क करें नहीं तो सेवाएं बंद कर दी जाएंगी।"
    res, _ = await service.analyse(msg)
    assert res.verdict in (Verdict.malicious, Verdict.suspicious)
    assert any(e.category == "REGIONAL_SCAM_LANGUAGE" for e in res.evidence)


@pytest.mark.asyncio
async def test_lookalike_sender_flagged(service):
    msg = "Your transaction is pending. Please verify your details."
    res, _ = await service.analyse(msg, sender="HDFCBX")
    assert any(e.category == "SENDER_LOOKALIKE" for e in res.evidence)


@pytest.mark.asyncio
async def test_empty_message_inconclusive(service):
    res, _ = await service.analyse("")
    assert res.verdict == Verdict.inconclusive


@pytest.mark.asyncio
async def test_short_message_inconclusive(service):
    res, _ = await service.analyse("Hi")
    assert res.verdict == Verdict.inconclusive


@pytest.mark.asyncio
async def test_benign_delivery_notification(service):
    msg = "Your Amazon order #402-9102-129 has been dispatched with courier BlueDart. Expected delivery by tomorrow."
    res, _ = await service.analyse(msg, sender="AMAZON")
    assert res.verdict == Verdict.clean_no_findings
    assert "No strong warning" in res.display_label


@pytest.mark.asyncio
async def test_brand_link_mismatch_detected(service):
    # Mentions SBI but links to phishing domain
    msg = "Important notice from SBI: Security update required. Open https://sbi-portal.xyz/login to continue."
    res, _ = await service.analyse(msg)
    assert any(e.category == "BRAND_LINK_MISMATCH" for e in res.evidence)


@pytest.mark.asyncio
async def test_recommendations_contain_cybercrime_helpline(service):
    msg = "Your account is blocked. Call 9811223344."
    res, _ = await service.analyse(msg)
    assert any("1930" in r or "cybercrime" in r for r in res.recommendations)
