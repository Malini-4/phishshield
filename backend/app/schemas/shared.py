"""Shared Pydantic schemas for PhishShield analysis results."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class Verdict(str, Enum):
    malicious = "malicious"
    suspicious = "suspicious"
    clean_no_findings = "clean_no_findings"
    inconclusive = "inconclusive"


class ModuleType(str, Enum):
    url = "url"
    apk = "apk"
    sms = "sms"
    screenshot = "screenshot"


DISPLAY_LABELS: Dict[str, Dict[str, str]] = {
    "url": {
        "malicious": "Likely malicious",
        "suspicious": "Suspicious link",
        "clean_no_findings": "No known threat found",
        "inconclusive": "Could not verify",
    },
    "apk": {
        "malicious": "Likely malicious",
        "suspicious": "Suspicious app",
        "clean_no_findings": "No strong warning signs found",
        "inconclusive": "Could not analyse",
    },
    "sms": {
        "malicious": "Likely scam",
        "suspicious": "Suspicious message",
        "clean_no_findings": "No strong warning signs found",
        "inconclusive": "Not enough evidence",
    },
    "screenshot": {
        "malicious": "Suspicious or inconsistent evidence",
        "suspicious": "Suspicious or inconsistent evidence",
        "clean_no_findings": "No obvious inconsistency detected",
        "inconclusive": "Could not analyse",
    },
}

# screenshot-specific override for clean_no_findings missing key fields
SCREENSHOT_IMPORTANT_MISSING = "Important details could not be read"


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"


class EvidenceSource(str, Enum):
    model = "model"
    rule = "rule"
    reputation = "reputation"
    parser = "parser"
    ocr = "ocr"


class CheckStatus(str, Enum):
    completed = "completed"
    failed = "failed"
    unavailable = "unavailable"
    skipped = "skipped"


class EvidenceItem(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    category: str
    severity: Severity
    title: str
    detail: str
    source: EvidenceSource


class CheckPerformed(BaseModel):
    name: str
    status: CheckStatus
    detail: Optional[str] = None


class AnalysisResult(BaseModel):
    investigation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: ModuleType
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    verdict: Verdict
    display_label: str
    summary: str
    evidence: List[EvidenceItem] = Field(default_factory=list)
    checks_performed: List[CheckPerformed] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    analysis_version: str = "1.0.0"
    model_version: Optional[str] = None
    input_summary: str = ""
    saved: bool = False
    case_id: Optional[str] = None


def make_display_label(module: str, verdict: Verdict) -> str:
    return DISPLAY_LABELS.get(module, {}).get(verdict.value, verdict.value)


STANDARD_RECOMMENDATIONS = {
    "malicious": [
        "Do not open this link, file, or follow instructions in this message.",
        "Do not enter any passwords, OTPs, PINs, card numbers, or personal details.",
        "If you have already interacted, change your passwords immediately and contact your bank.",
        "Report to the National Cyber Crime portal at cybercrime.gov.in or helpline 1930 (India).",
        "Verify through the official app or website of the brand directly.",
    ],
    "suspicious": [
        "Exercise caution. Do not proceed until you can verify through official channels.",
        "Do not enter passwords, OTPs, or financial details.",
        "Contact the brand through its official app/website—not through any number or link provided.",
        "Report suspicious content at cybercrime.gov.in or helpline 1930 (India).",
    ],
    "clean_no_findings": [
        "No known threats were detected, but this is not a guarantee of safety.",
        "Always verify the website address matches what you expect before entering any credentials.",
        "When in doubt, open your bank/service app directly rather than clicking links.",
    ],
    "inconclusive": [
        "The analysis could not reach a confident verdict.",
        "Treat the content with caution until independently verified.",
        "If you suspect a scam, report it at cybercrime.gov.in or helpline 1930 (India).",
    ],
}


def standard_recommendations(verdict: Verdict) -> List[str]:
    return STANDARD_RECOMMENDATIONS.get(verdict.value, [])
