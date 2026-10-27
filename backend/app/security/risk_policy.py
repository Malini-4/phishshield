"""
Risk policy for URL analysis – deterministic decision table.
Produces a Verdict from model score + rule results + reputation findings.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from app.schemas.shared import (
    AnalysisResult,
    CheckPerformed,
    CheckStatus,
    EvidenceItem,
    EvidenceSource,
    ModuleType,
    Severity,
    Verdict,
    make_display_label,
    standard_recommendations,
)
from app.security.url_rules import RuleResult

logger = logging.getLogger(__name__)

"""
Decision Table (executed in order; first match wins):
────────────────────────────────────────────────────────────────────────────────
1. LIKELY MALICIOUS if ANY of:
   a. Any reputation source returns 'match'
   b. model_score >= malicious_threshold AND ≥1 medium/high rule fired
   c. ≥2 HIGH-severity rules fired (any combination)
   d. USERINFO_TRICK or PUNYCODE_LOOKALIKE or MIXED_SCRIPT + any other high rule

2. SUSPICIOUS if ANY of:
   a. model_score >= suspicious_threshold
   b. ≥1 HIGH-severity rule fired
   c. ≥2 MEDIUM-severity rules fired
   d. TUNNEL + BRAND_IN_SUBDOMAIN + (high model OR credential-style path)

3. NO KNOWN THREAT if ALL of:
   a. Model was available and scored below suspicious_threshold
   b. No medium/high rules fired
   c. At least one reputation source completed (no_match) OR none configured
   → always show caveat

4. COULD NOT VERIFY otherwise (model unavailable + no strong signals, or
   signals conflict, or input ambiguous, or key checks failed)
"""


@dataclass
class ReputationResult:
    source: str
    status: str  # match | no_match | error | unconfigured | stale
    detail: Optional[str] = None
    listed_at: Optional[str] = None
    threat_type: Optional[str] = None


def decide_verdict(
    rule_results: list[RuleResult],
    reputation_results: list[ReputationResult],
    model_score: Optional[float],
    model_available: bool,
    malicious_threshold: float,
    suspicious_threshold: float,
    model_check_status: CheckStatus,
) -> Verdict:
    """
    Deterministic policy. Returns a Verdict enum value.
    """
    # Count rule hits by severity
    high_rules = [r for r in rule_results if r.fired and r.severity == Severity.high]
    medium_rules = [r for r in rule_results if r.fired and r.severity == Severity.medium]
    tunnel_fired = any(r.rule_id == "TUNNEL_OR_FREE_HOSTING" and r.fired for r in rule_results)
    brand_sub_fired = any(r.rule_id == "BRAND_IN_SUBDOMAIN_NOT_REGISTRABLE" and r.fired for r in rule_results)

    # Check reputation
    rep_matches = [r for r in reputation_results if r.status == "match"]
    rep_no_match = [r for r in reputation_results if r.status == "no_match"]
    rep_completed = rep_matches + rep_no_match

    # ── STEP 1: Likely malicious ─────────────────────────────────────────────
    if rep_matches:
        return Verdict.malicious

    if (model_available
            and model_score is not None
            and model_score >= malicious_threshold
            and (high_rules or medium_rules)):
        return Verdict.malicious

    if len(high_rules) >= 2:
        return Verdict.malicious

    # ── STEP 2: Suspicious ──────────────────────────────────────────────────
    if model_available and model_score is not None and model_score >= suspicious_threshold:
        return Verdict.suspicious

    if len(high_rules) >= 1:
        return Verdict.suspicious

    if len(medium_rules) >= 2:
        return Verdict.suspicious

    if tunnel_fired and brand_sub_fired:
        return Verdict.suspicious

    # ── STEP 3: No known threat found ───────────────────────────────────────
    if (model_available
            and model_score is not None
            and model_score < suspicious_threshold
            and not high_rules
            and not medium_rules):
        return Verdict.clean_no_findings

    # ── STEP 4: Could not verify ─────────────────────────────────────────────
    return Verdict.inconclusive


def build_checks(
    model_available: bool,
    model_check_status: CheckStatus,
    model_check_detail: str,
    reputation_results: list[ReputationResult],
    parser_ok: bool,
    rules_ran: bool,
) -> list[CheckPerformed]:
    checks = []

    checks.append(CheckPerformed(
        name="URL parsing",
        status=CheckStatus.completed if parser_ok else CheckStatus.failed,
        detail="URL successfully parsed into components." if parser_ok else "URL parsing failed.",
    ))

    checks.append(CheckPerformed(
        name="Security rules",
        status=CheckStatus.completed if rules_ran else CheckStatus.failed,
        detail="All rule checks applied." if rules_ran else "Rule checks could not run.",
    ))

    checks.append(CheckPerformed(
        name="ML model scoring",
        status=model_check_status,
        detail=model_check_detail,
    ))

    for rep in reputation_results:
        status_map = {
            "match": CheckStatus.completed,
            "no_match": CheckStatus.completed,
            "error": CheckStatus.failed,
            "unconfigured": CheckStatus.unavailable,
            "stale": CheckStatus.completed,
        }
        detail_map = {
            "match": f"URL listed: {rep.detail or rep.threat_type or 'threat detected'}",
            "no_match": "Not found in this feed.",
            "error": f"Lookup failed: {rep.detail or 'unknown error'}",
            "unconfigured": "API key not configured.",
            "stale": f"Feed data is stale. {rep.detail or ''}",
        }
        checks.append(CheckPerformed(
            name=f"Reputation: {rep.source}",
            status=status_map.get(rep.status, CheckStatus.failed),
            detail=detail_map.get(rep.status, rep.detail or ""),
        ))

    return checks


STANDARD_LIMITATIONS = [
    "This analysis is based on static URL features, security rules, and optional threat-intelligence feeds. "
    "It cannot guarantee safety.",
    "Phishing sites frequently change domains. A URL not found in reputation feeds may still be malicious.",
    "No DNS lookups or page content is fetched; analysis is URL-structure only (plus reputation feeds if configured).",
    "Brand impersonation checks rely on a curated reference list and may miss unknown brands or new official domains.",
]
