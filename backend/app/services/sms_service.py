"""
SMS Analysis Service – text analysis + sender verification.
"""
from __future__ import annotations

import csv
import hashlib
import logging
import re
import unicodedata
import uuid
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Optional

from app.config import get_settings
from app.schemas.shared import (
    AnalysisResult, CheckPerformed, CheckStatus, EvidenceItem, EvidenceSource,
    ModuleType, Severity, Verdict, make_display_label, standard_recommendations,
)
from app.security.domain_checks import check_domain, load_brand_domains
from app.security.url_parser import parse_url
from app.services.sms_text import expand_shorthand, split_sender

logger = logging.getLogger(__name__)
_DATA_DIR = Path(__file__).parent.parent.parent.parent / "data" / "reference"

# ── Sender reference ──────────────────────────────────────────────────────────

@lru_cache(maxsize=1)
def load_sender_reference() -> list[dict]:
    path = _DATA_DIR / "sms_sender_reference.csv"
    entries = []
    if not path.exists():
        return entries
    try:
        with open(path, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                entries.append(dict(row))
    except Exception as e:
        logger.error(f"Failed to load SMS sender reference: {e}")
    return entries


def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def verify_sender(sender: Optional[str]) -> dict:
    """
    Returns {state, brand, source, detail}
    States: exact_match | possible_lookalike | unverified | unavailable | malformed
    Handles standard Indian DLT headers:
    - 6-character header (e.g. 'SBIINB')
    - 2-letter operator/circle prefix + '-' + header (e.g. 'VK-SBIINB', 'AD-HDFCBK', 'CP-AMAZON')
    """
    if not sender or not sender.strip():
        return {
            "state": "unavailable",
            "brand": None,
            "source": None,
            "detail": "No sender ID provided.",
        }

    raw = sender.strip()

    # Check for mobile numbers used as sender (e.g., 10 digits or with +91)
    cleaned_digits = re.sub(r"[\s\-\+]", "", raw)
    if re.match(r"^(?:91)?[6-9]\d{9}$", cleaned_digits) or re.match(r"^\d{10,}$", cleaned_digits):
        return {
            "state": "malformed",
            "brand": None,
            "source": None,
            "detail": f"Sender '{raw}' appears to be a personal mobile number, not a registered commercial DLT header. "
                       "Banks and legitimate enterprises send transactional alerts via registered alpha headers, not mobile numbers.",
        }

    reference = load_sender_reference()
    if not reference:
        return {
            "state": "unavailable",
            "brand": None,
            "source": None,
            "detail": "Sender reference data is not loaded.",
        }

    # Extract core header using split_sender (supports VK-SBIINB, vk SBIINB, VK_SBIINB, etc.)
    header_core = split_sender(raw)

    # Exact match check (also accept an 8-character glued form like VKHDFCBK)
    for entry in reference:
        ref_h = entry["header"].upper()
        if (
            header_core == ref_h
            or raw.upper() == ref_h
            or (len(header_core) == 8 and header_core[:2].isalpha() and header_core[2:] == ref_h)
        ):
            return {
                "state": "exact_match",
                "brand": entry.get("brand"),
                "source": entry.get("source_url"),
                "detail": f"Matches verified DLT header for {entry.get('brand')} (Source: {entry.get('source_url')}).",
            }

    # Lookalike check
    candidate_header = header_core[2:] if (len(header_core) == 8 and header_core[:2].isalpha()) else header_core
    for entry in reference:
        ref_h = entry["header"].upper()
        dist1 = _levenshtein(header_core, ref_h) if len(header_core) >= 4 else 99
        dist2 = _levenshtein(candidate_header, ref_h) if len(candidate_header) >= 4 else 99
        dist = min(dist1, dist2)
        if 0 < dist <= 1:
            return {
                "state": "possible_lookalike",
                "brand": entry.get("brand"),
                "source": entry.get("source_url"),
                "detail": f"Sender '{raw}' closely resembles verified header '{ref_h}' for {entry.get('brand')} "
                           f"(edit distance: {dist}). This could be an impersonation attempt.",
            }

    return {
        "state": "unverified",
        "brand": None,
        "source": None,
        "detail": f"Sender '{raw}' is well-formed but not present in the verified reference dataset. "
                   "This does not guarantee it is fraudulent, as reference coverage is limited.",
    }


# ── Text Normalisation ────────────────────────────────────────────────────────

def normalise_text(text: str) -> str:
    # NFKC normalisation
    text = unicodedata.normalize("NFKC", text)
    # Remove zero-width chars and invisible codepoints
    text = re.sub(r"[\u200b-\u200f\u2028\u2029\ufeff\xad]", "", text)
    return text


# ── URL Extraction from SMS ───────────────────────────────────────────────────

# Match standard http/https, hxxp, and obfuscated domain forms
URL_REGEX = re.compile(
    r"(?:https?://[^\s\]\[\"'<>]+|hxxps?://[^\s\]\[\"'<>]+|[a-zA-Z0-9.\-]+\.(?:com|org|net|in|co\.in|gov\.in|xyz|top|app|dev|me|site|live|click|link|cc|tk|ml|ga|cf|gq|work|info|biz|online|store|tech|club|vip)[/\w\-.~:?#\[\]@!$&'()*+,;=%]*)",
    re.IGNORECASE,
)
OBFUSCATED_SHORTENER_REGEX = re.compile(
    r"\b(?:bit|tinyurl|is|t|goo|cutt|rb|shorturl)\s*[\[\(\.\s\]\)]+\s*(?:ly|gl|com|co|gd)\b",
    re.IGNORECASE,
)


def extract_urls_from_sms(text: str) -> list[str]:
    found = []
    # De-obfuscate common patterns before extracting
    deobf = text.replace("[.]", ".").replace("(.)", ".").replace("hxxp://", "http://").replace("hxxps://", "https://")
    for m in URL_REGEX.finditer(deobf):
        url = m.group(0).strip(".,;:?!'\"()[]{}")
        if "." in url and not url.endswith("."):
            # Ensure not just a number or email
            if not re.match(r"^\d+\.\d+$", url) and "@" not in url:
                found.append(url)

    if OBFUSCATED_SHORTENER_REGEX.search(text):
        found.append("[obfuscated-shortener]")

    # Deduplicate while preserving order
    return list(dict.fromkeys(found))


# ── Rule Engine Patterns ──────────────────────────────────────────────────────

# Explicit negation indicators (bank warnings like "Never share OTP")
LEGITIMATE_OTP_WARNING_PATTERNS = [
    r"(?:do\s+not|never|don'?t|should\s+not|not\s+to\s+be)\s+(?:share|disclose|give|reveal|tell)",
    r"(?:bank\s+never\s+asks|never\s+ask\s+for)",
    r"kisi\s+ko\s+bhi\s+otp\s+na\s+de",
    r"kisi\s+se\s+share\s+na\s+kare",
    r"kabhi\s+bhi\s+share\s+na\s+kare",
]

# Credential request patterns
CREDENTIAL_STEAL_PATTERNS = [
    (r"(?:share|send|provide|enter|submit|update|verify|confirm)\s+(?:your\s+)?(?:otp|one\s*time\s*password|pin|mpin|cvv|password|passcode|card\s*details|netbanking\s*credentials)", "Requests sharing or entry of sensitive credentials (OTP/PIN/Password)"),
    (r"(?:enter|fill\s*in)\s+(?:your\s+)?(?:aadhaar|pan\s*card|debit\s*card|credit\s*card)\s+(?:details|number)\s+(?:at|on|here|via)", "Demands Aadhaar/PAN or card details"),
    (r"(?:forward|send)\s+this\s+(?:sms|message|otp)\s+to", "Requests forwarding confidential SMS or OTP"),
]

URGENCY_PATTERNS = [
    (r"(?:account|services?|sim|card|electricity|power)\s+(?:will\s+be\s+|has\s+been\s+)?(?:blocked|suspended|deactivated|disconnected|frozen|closed|terminated|stopped)\s*(?:today|within|immediately|by|in\s*\d+\s*(?:hrs|hours|mins|days))?", "Threatens immediate suspension, blocking, or disconnection"),
    (r"(?:legal\s+action|police\s+complaint|court\s+notice|arrest\s+warrant|fir\s+lodged)", "Threatens legal, police, or judicial action"),
    (r"immediate\s+action\s+required|urgent\s+attention|act\s+now|last\s+chance|final\s+warning", "Creates psychological urgency and pressure"),
]

KYC_PATTERNS = [
    (r"(?:update|complete|verify|link|submit|renew)\s+(?:your|the|ur)\s+(?:kyc|pan|aadhaar)", "Demands user to update/complete/verify/link/submit/renew KYC or identification details"),
    (r"kyc\s+(?:is\s+required|has\s+expired|not\s+updated|mandatory|pending|suspended|incomplete)", "Warning that KYC is required, has expired, or is not updated"),
    (r"(?:kyc|pan|aadhaar)\s*(?:update|verification|pending|expired|suspended|mandatory|link|incomplete)", "Demands urgent KYC / document update"),
    (r"update\s+your\s+kyc|complete\s+your\s+kyc|kyc\s+is\s+required", "Requests user to complete KYC to prevent penalties"),
]

WRONG_PAYMENT_PATTERNS = [
    (r"(?:paid|sent|transferred).{0,40}(?:by\s+mistake|by\s+error|accidentally).{0,60}(?:send\s+it\s+back|return\s+it|refund\s+it|transfer\s+back|pay\s+back|send\s+back)", "Wrong-payment / paid-by-mistake refund scam"),
    (r"(?:by\s+mistake|by\s+error|accidentally).{0,50}(?:send\s+it\s+back|return\s+it|refund\s+it|transfer\s+back|pay\s+back|send\s+back)", "Claims accidental payment and requests money sent back"),
    (r"(?:sent|paid)\s+to\s+wrong\s+(?:account|upi|number).{0,60}(?:return|refund|send\s+back)", "Wrong-account payment scam"),
    (r"(?:by\s+mistake|accidentally).{0,30}(?:money\s+transferred|amount\s+sent|rs\.?\s*\d+|₹\s*\d+).{0,50}(?:return|send\s+back|refund)", "Claims payment sent by mistake and requests return of funds"),
]

LAW_ENFORCEMENT_PATTERNS = [
    (r"digital\s+arrest", "Fabricated 'digital arrest' extortion threat"),
    (r"money\s+laundering", "False money laundering accusation used for extortion"),
    (r"(?:cbi|customs|cyber\s*crime)\s*(?:officer|dept|department|notice|investigation|inspector|cell)", "Law enforcement or customs officer impersonation"),
    (r"(?:police\s+officer|crime\s+branch|narcotics\s+control|enforcement\s+directorate)", "Police or enforcement directorate impersonation"),
]

FINANCIAL_SCAM_PATTERNS = [
    (r"(?:refund|cashback|reward|bonus|prize|lottery)\s+(?:of\s+)?(?:rs\.?|inr|₹)?\s*[\d,]+", "Claims entitlement to unrequested refund, cashback, or prize"),
    (r"(?:congratulations|selected|winner)\b.{0,50}(?:won|claim|gift|reward)", "Promises prize/lottery winnings"),
    (r"(?:part\s*time\s*job|work\s*from\s*home|earn\s*(?:rs\.?|inr|₹)?\s*[\d,]+\s*(?:daily|per\s*day|monthly))", "Advertises work-from-home or job earnings scam"),
    (r"(?:instant\s*loan|pre-?approved\s*(?:personal\s*)?loan|loan\s*sanctioned)\s*(?:of\s*)?(?:rs\.?|inr|₹)?\s*[\d,]+", "Unsolicited loan approval scheme"),
    (r"(?:task|youtube\s*like|telegram\s*group|crypto\s*investment).{0,30}(?:earn|profit|income|guaranteed)", "Task-based or investment scam scheme"),
    (r"(?:electricity\s*bill|power\s*bill)\s*(?:unpaid|pending|due)", "Electricity bill disconnection scam"),
    (r"(?:delivery\s*failed|address\s*incomplete|package\s*on\s*hold|customs\s*fee)", "Parcel/courier delivery fee scam"),
]

# Hinglish & Devanagari scam terms
MULTILINGUAL_PATTERNS = [
    (r"(?:aapka|apka)\s+(?:khata|account|sim|bijli|bijlee)\s+(?:band|block|suspend)\s+(?:ho\s+jayega|kar\s+diya\s+gaya)", "Hinglish: Threatens account or utility blocking ('band ho jayega')"),
    (r"(?:turant|jaldi)\s+(?:sampark\s+kare|kall\s+kare|update\s+kare|click\s+kare)", "Hinglish: Urges immediate action ('turant sampark kare')"),
    (r"(?:खाता|सिम|बिजली)\s*(?:बंद|ब्लॉक|निलंबित)", "Devanagari: Warning of account or utility suspension"),
    (r"(?:तुरंत|जल्दी)\s*(?:संपर्क\s*करें|अपडेट\s*करें|क्लिक\s*करें)", "Devanagari: Urgent action demand"),
]

PHONE_CALLBACK_PATTERN = re.compile(
    r"(?:call|contact|reach|dial|helpline|care\s*no|officer\s*at)[:\s]+(?:\+?91[\s\-]?)?([6-9]\d{9}|1800\d{6,7})",
    re.IGNORECASE,
)


def _has_legitimate_warning(text: str) -> bool:
    t_lower = text.lower()
    return any(re.search(p, t_lower, re.IGNORECASE) for p in LEGITIMATE_OTP_WARNING_PATTERNS)


def analyse_sms_text(
    text: str,
    sender_result: dict,
    extracted_urls: list[str],
) -> list[EvidenceItem]:
    evidence: list[EvidenceItem] = []
    expanded = expand_shorthand(text)
    norm = normalise_text(expanded)
    norm_lower = norm.lower()
    is_legit_warning = _has_legitimate_warning(text) or _has_legitimate_warning(expanded)

    # 1. Credential theft check
    has_cred_attempt = False
    for pat, desc in CREDENTIAL_STEAL_PATTERNS:
        if re.search(pat, norm_lower):
            has_cred_attempt = True
            if not is_legit_warning:
                evidence.append(EvidenceItem(
                    category="CREDENTIAL_REQUEST",
                    severity=Severity.high,
                    title="Demands sensitive credentials",
                    detail=f"Message explicitly asks you to share or enter sensitive credentials: {desc}. "
                           "Legitimate financial institutions never ask for your passwords, OTP, or PIN.",
                    source=EvidenceSource.rule,
                ))
            break

    # If it has a legitimate warning and NO request to share credentials, record benign indicator
    if is_legit_warning and not has_cred_attempt:
        evidence.append(EvidenceItem(
            category="LEGITIMATE_SECURITY_BOILERPLATE",
            severity=Severity.info,
            title="Standard bank security warning present",
            detail="The message contains official security advice ('Do not share OTP / PIN'). "
                   "This is common in legitimate transactional and OTP notifications.",
            source=EvidenceSource.rule,
        ))

    # 2. Urgency and threats
    for pat, desc in URGENCY_PATTERNS:
        if re.search(pat, norm_lower):
            evidence.append(EvidenceItem(
                category="URGENCY_PRESSURE",
                severity=Severity.medium,
                title="Coercive urgency or threat detected",
                detail=f"{desc}. Scammers create artificial panic to prompt hasty compliance.",
                source=EvidenceSource.rule,
            ))
            break

    # 3. KYC demands
    for pat, desc in KYC_PATTERNS:
        if re.search(pat, norm_lower):
            evidence.append(EvidenceItem(
                category="KYC_DEMAND",
                severity=Severity.medium,
                title="Unsolicited KYC verification demand",
                detail=f"{desc}. Banks do not update KYC via random links or third-party phone numbers.",
                source=EvidenceSource.rule,
            ))
            break

    # 4. Financial & lottery/refund scams
    for pat, desc in FINANCIAL_SCAM_PATTERNS:
        if re.search(pat, norm_lower):
            evidence.append(EvidenceItem(
                category="FINANCIAL_SCAM_INDICATOR",
                severity=Severity.medium,
                title="Common scam lure detected",
                detail=f"{desc}.",
                source=EvidenceSource.rule,
            ))
            break

    # 4b. Wrong payment scam
    for pat, desc in WRONG_PAYMENT_PATTERNS:
        if re.search(pat, norm_lower):
            evidence.append(EvidenceItem(
                category="WRONG_PAYMENT_SCAM",
                severity=Severity.medium,
                title="Wrong-payment refund scam lure",
                detail=f"{desc}. Scammers pretend to have transferred money accidentally to trick victims into sending real funds.",
                source=EvidenceSource.rule,
            ))
            break

    # 4c. Law enforcement impersonation / digital arrest
    for pat, desc in LAW_ENFORCEMENT_PATTERNS:
        if re.search(pat, norm_lower):
            evidence.append(EvidenceItem(
                category="LAW_ENFORCEMENT_IMPERSONATION",
                severity=Severity.high,
                title="Law enforcement impersonation or 'digital arrest' threat",
                detail=f"{desc}. Official agencies never arrest citizens virtually or demand compliance over SMS.",
                source=EvidenceSource.rule,
            ))
            break

    # 5. Multilingual / Hinglish indicators
    for pat, desc in MULTILINGUAL_PATTERNS:
        if re.search(pat, norm):
            evidence.append(EvidenceItem(
                category="REGIONAL_SCAM_LANGUAGE",
                severity=Severity.medium,
                title="Regional scam language detected",
                detail=f"{desc}.",
                source=EvidenceSource.rule,
            ))
            break

    # 6. Phone callback combined with urgency
    phone_match = PHONE_CALLBACK_PATTERN.search(norm)
    if phone_match and any(e.category in ("URGENCY_PRESSURE", "KYC_DEMAND", "REGIONAL_SCAM_LANGUAGE") for e in evidence):
        evidence.append(EvidenceItem(
            category="UNOFFICIAL_PHONE_CALLBACK",
            severity=Severity.medium,
            title="Unsolicited support contact number provided",
            detail=f"Message provides callback number '{phone_match.group(1)}' alongside urgency/KYC demands. "
                   "Scammers frequently host fake customer-support numbers.",
            source=EvidenceSource.rule,
        ))

    # 7. Brand impersonation with mismatching link
    # Check if a known brand is named in the text while a link in the SMS points to a non-official domain
    brands = load_brand_domains()
    for brand in brands:
        b_name = brand.brand.lower()
        if b_name in norm_lower:
            for u in extracted_urls:
                if u != "[obfuscated-shortener]":
                    p = parse_url(u)
                    if not isinstance(p, Exception) and hasattr(p, "registrable_domain"):
                        d_res = check_domain(p.registrable_domain, p.subdomain, p.path, p.host)
                        if not d_res.is_official and p.registrable_domain:
                            evidence.append(EvidenceItem(
                                category="BRAND_LINK_MISMATCH",
                                severity=Severity.high,
                                title=f"Brand impersonation with mismatched URL",
                                detail=f"The text mentions '{brand.brand}', but links to '{p.registrable_domain}', "
                                       f"which is not an official domain for {brand.brand}.",
                                source=EvidenceSource.rule,
                            ))
                            break

    # 8. Sender verification findings
    if sender_result.get("state") == "malformed":
        evidence.append(EvidenceItem(
            category="SENDER_MALFORMED",
            severity=Severity.medium,
            title="Unofficial sender identifier (mobile number)",
            detail=sender_result["detail"],
            source=EvidenceSource.parser,
        ))
    elif sender_result.get("state") == "possible_lookalike":
        evidence.append(EvidenceItem(
            category="SENDER_LOOKALIKE",
            severity=Severity.high,
            title="Sender ID mimics a verified organization",
            detail=sender_result["detail"],
            source=EvidenceSource.parser,
        ))
    elif sender_result.get("state") == "exact_match":
        evidence.append(EvidenceItem(
            category="SENDER_VERIFIED",
            severity=Severity.info,
            title="Sender matches verified DLT header",
            detail=f"{sender_result['detail']} Note: Header match alone does not guarantee authenticity due to potential threading or spoofing.",
            source=EvidenceSource.parser,
        ))

    # 9. Obfuscated shorteners in SMS
    if "[obfuscated-shortener]" in extracted_urls:
        evidence.append(EvidenceItem(
            category="OBFUSCATED_SHORTENER",
            severity=Severity.medium,
            title="Obfuscated URL shortener detected in text",
            detail="The message disguises a URL shortener using bracket or space manipulation to bypass automated spam filters.",
            source=EvidenceSource.rule,
        ))

    return evidence


def _decide_sms_verdict(
    evidence: list[EvidenceItem],
    text: str,
    sender_result: Optional[dict] = None,
) -> Verdict:
    if len(text.strip()) < 5:
        return Verdict.inconclusive

    high_count = sum(1 for e in evidence if e.severity == Severity.high)
    medium_count = sum(1 for e in evidence if e.severity == Severity.medium)

    if high_count >= 1:
        return Verdict.malicious

    if medium_count >= 1:
        return Verdict.suspicious

    # No rule found anything (no high, no medium)
    # Return clean_no_findings ONLY when the sender is an exact verified DLT match,
    # or a standard bank "do not share OTP" warning is present. Otherwise return inconclusive.
    has_exact_sender = (
        (sender_result is not None and sender_result.get("state") == "exact_match")
        or any(e.category == "SENDER_VERIFIED" for e in evidence)
    )
    has_otp_warning = (
        _has_legitimate_warning(text)
        or any(e.category == "LEGITIMATE_SECURITY_BOILERPLATE" for e in evidence)
    )

    if has_exact_sender or has_otp_warning:
        return Verdict.clean_no_findings

    return Verdict.inconclusive


def _redact_sensitive(text: str) -> str:
    """Mask OTPs, cards, phone numbers, and Aadhaar numbers for privacy."""
    # 6-digit OTP
    t = re.sub(r"\b\d{6}\b", "[REDACTED-OTP]", text)
    # 12-digit Aadhaar
    t = re.sub(r"\b\d{4}\s*\d{4}\s*\d{4}\b", "[REDACTED-AADHAAR]", t)
    # 16-digit credit/debit card
    t = re.sub(r"\b(?:\d{4}[-\s]?){3}\d{4}\b", "[REDACTED-CARD]", t)
    # 10-digit mobile number
    t = re.sub(r"\b(?:\+?91[\s\-]?)?[6-9]\d{9}\b", "[REDACTED-PHONE]", t)
    return t


class SmsAnalysisService:
    def __init__(self):
        self.settings = get_settings()

    async def analyse(
        self, message: str, sender: Optional[str] = None
    ) -> tuple[AnalysisResult, Optional[dict]]:
        t_start = datetime.now(timezone.utc)
        investigation_id = str(uuid.uuid4())
        created_at = t_start.isoformat()

        checks: list[CheckPerformed] = []
        limitations = [
            "SMS analysis uses a layered rule and pattern engine. It cannot verify whether third-party phone numbers or backend systems are currently active.",
            "A registered sender header (DLT) is not an absolute guarantee of legitimacy due to potential spoofing or compromised credentials.",
            "No personal messages or sensitive credentials should ever be transmitted across unencrypted channels.",
            "English and Hinglish are comprehensively evaluated; coverage for other Indian regional scripts is limited to known keyword lists.",
        ]

        if not message or len(message.strip()) < 5:
            verdict = Verdict.inconclusive
            result = AnalysisResult(
                investigation_id=investigation_id,
                type=ModuleType.sms,
                created_at=created_at,
                verdict=verdict,
                display_label=make_display_label("sms", verdict),
                summary="The message is too short or empty to analyse reliably.",
                checks_performed=[
                    CheckPerformed(
                        name="Input validation",
                        status=CheckStatus.failed,
                        detail="Message text must be at least 5 characters long.",
                    )
                ],
                limitations=limitations,
                recommendations=standard_recommendations(verdict),
            )
            return result, None

        checks.append(CheckPerformed(
            name="Input validation",
            status=CheckStatus.completed,
            detail=f"Parsed {len(message)} characters.",
        ))

        # Sender verification
        sender_result = verify_sender(sender)
        checks.append(CheckPerformed(
            name="Sender header verification",
            status=CheckStatus.completed if sender else CheckStatus.skipped,
            detail=sender_result["detail"],
        ))

        # URL extraction
        extracted_urls = extract_urls_from_sms(message)
        checks.append(CheckPerformed(
            name="Embedded link extraction",
            status=CheckStatus.completed,
            detail=f"Detected {len(extracted_urls)} link(s) or shortener(s)." if extracted_urls else "No links found in message.",
        ))

        # Rule evaluation
        evidence = analyse_sms_text(message, sender_result, extracted_urls)
        checks.append(CheckPerformed(
            name="Text scam rules",
            status=CheckStatus.completed,
            detail=f"Evaluated rules; {len(evidence)} evidence finding(s).",
        ))

        # ML model prediction
        model_version: Optional[str] = None
        try:
            from app.services.sms_ml import predict_sms
            ml_pred = predict_sms(message)
            if ml_pred.get("available"):
                model_version = ml_pred.get("model_version")
                prob = ml_pred.get("scam_probability", 0.0)
                if prob >= 0.85:
                    evidence.append(EvidenceItem(
                        category="ML_SCAM_LANGUAGE",
                        severity=Severity.medium,
                        title="Scam language model indicates high risk",
                        detail=f"Scam language classification probability: {prob:.1%}.",
                        source=EvidenceSource.model,
                    ))
                elif prob >= 0.50:
                    evidence.append(EvidenceItem(
                        category="ML_SCAM_LANGUAGE",
                        severity=Severity.low,
                        title="Scam language model indicates moderate risk",
                        detail=f"Scam language classification probability: {prob:.1%}.",
                        source=EvidenceSource.model,
                    ))
                checks.append(CheckPerformed(
                    name="Scam language model",
                    status=CheckStatus.completed,
                    detail=f"Probability {prob:.1%} ({ml_pred.get('band', 'unknown')}).",
                ))
            else:
                checks.append(CheckPerformed(
                    name="Scam language model",
                    status=CheckStatus.unavailable,
                    detail="Model unavailable or not trained.",
                ))
        except Exception as e:
            logger.debug(f"SMS ML prediction failed: {e}")
            checks.append(CheckPerformed(
                name="Scam language model",
                status=CheckStatus.unavailable,
                detail=str(e),
            ))

        verdict = _decide_sms_verdict(evidence, message, sender_result)
        display_label = make_display_label("sms", verdict)

        # Summary formation
        summary = _build_sms_summary(verdict, evidence, sender_result, extracted_urls)

        # Recommendations
        recommendations = standard_recommendations(verdict)
        if extracted_urls:
            recommendations.append(
                "Do not click or tap any links in the message. You can copy the link and examine it individually in the URL Threat Analysis module."
            )
        recommendations.append(
            "Forward fraudulent SMS to 1909 (TRAI DND registry) or report immediately to https://cybercrime.gov.in / Helpline 1930."
        )

        # Redact for privacy
        redacted = _redact_sensitive(message) if not self.settings.STORE_FULL_SMS_TEXT else message
        msg_hash = hashlib.sha256(message.encode("utf-8")).hexdigest()

        result = AnalysisResult(
            investigation_id=investigation_id,
            type=ModuleType.sms,
            created_at=created_at,
            verdict=verdict,
            display_label=display_label,
            summary=summary,
            evidence=evidence,
            checks_performed=checks,
            limitations=limitations,
            recommendations=recommendations,
            analysis_version="1.0.0",
            model_version=model_version,
            input_summary=f"SMS ({len(message)} chars)" + (f" from {sender}" if sender else ""),
        )

        sms_details = {
            "sender": sender,
            "sender_state": sender_result["state"],
            "message_hash": msg_hash,
            "redacted_text": redacted[:2000],
            "extracted_urls": extracted_urls[:10],
            "message_length": len(message),
        }

        return result, sms_details


def _build_sms_summary(verdict: Verdict, evidence: list[EvidenceItem], sender_result: dict, urls: list[str]) -> str:
    if verdict == Verdict.malicious:
        high_ev = [e for e in evidence if e.severity == Severity.high]
        reason = high_ev[0].title if high_ev else "critical scam indicators"
        return f"This message exhibits strong warning signs of a scam ({reason}). Do not respond, click links, or share any codes."
    if verdict == Verdict.suspicious:
        med_ev = [e for e in evidence if e.severity in (Severity.high, Severity.medium)]
        reason = med_ev[0].title if med_ev else "suspicious characteristics"
        return f"This message shows suspicious characteristics ({reason}). Verify with the sender via official channels before taking action."
    if verdict == Verdict.clean_no_findings:
        return "No strong warning signs were found in this message, but this is not proof of safety. Always verify unexpected notifications directly with your provider."
    return "Not enough evidence to verify this message. Exercise caution and verify directly with the sender or provider."
