"""
URL Analysis Service – orchestrates parsing, features, rules, model, reputation, policy.
"""
from __future__ import annotations

import hashlib
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

from app.config import get_settings
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
from app.security.domain_checks import check_domain, enrich_features
from app.security.risk_policy import (
    ReputationResult,
    STANDARD_LIMITATIONS as RL,
    build_checks,
    decide_verdict,
)
from app.security.url_features import extract_features, FEATURE_NAMES
from app.security.url_parser import ParsedUrl, ValidationError, parse_url
from app.security.url_rules import fired_to_evidence, run_url_rules
from app.services.model_loader import get_model
from app.services.reputation_service import check_url_reputation

logger = logging.getLogger(__name__)

# Override limitations to use risk_policy's version
LIMITATIONS = [
    "Analysis is based on URL structure, security rules, and optional threat-intelligence feeds only. "
    "It does not fetch or render the page.",
    "Phishing sites change domains frequently. A clean result is NOT a guarantee of safety.",
    "No DNS lookups are performed to protect privacy. Domain registration age is not checked.",
    "Brand impersonation checks rely on a curated list that may not cover all brands.",
    "The ML model was trained on historical data; novel attacks may not be detected.",
]


class UrlAnalysisService:
    def __init__(self):
        self.settings = get_settings()

    async def analyse(
        self,
        url_input: str,
        db_session=None,
    ) -> tuple[AnalysisResult, Optional[dict]]:
        """
        Analyse a URL and return (AnalysisResult, url_details_dict).
        url_details_dict contains parsed components and scores for storage.
        Raises ValueError with user-friendly message if input is invalid.
        """
        t_start = time.perf_counter()
        investigation_id = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc).isoformat()

        # ── 1. Parse URL ──────────────────────────────────────────────────
        parsed = parse_url(url_input)
        if isinstance(parsed, ValidationError):
            raise ValueError(f"{parsed.message}")

        # ── 2. Domain checks ──────────────────────────────────────────────
        domain_result = check_domain(
            registrable_domain=parsed.registrable_domain,
            subdomain=parsed.subdomain,
            path=parsed.path,
            host=parsed.host,
        )

        # ── 3. Feature extraction ─────────────────────────────────────────
        features = extract_features(parsed)
        features = enrich_features(features, domain_result)

        # ── 4. Security rules ─────────────────────────────────────────────
        rule_results = run_url_rules(parsed, domain_result)
        rule_evidence = fired_to_evidence(rule_results)

        # ── 5. ML model scoring ───────────────────────────────────────────
        model, model_error = get_model()
        model_available = model is not None
        model_score: Optional[float] = None
        model_band_str: Optional[str] = None

        if model_available:
            try:
                model_score = model.score(features)
                model_band_str = model.band(model_score)
                model_check_status = CheckStatus.completed
                model_check_detail = f"Scored. Band: {model_band_str}."
                model_evidence = EvidenceItem(
                    category="MODEL_SCORE",
                    severity=Severity.info,
                    title="ML model assessment",
                    detail=f"Model places this URL in the '{model_band_str}' risk band. "
                           "This is one of several signals; see rules and reputation above.",
                    source=EvidenceSource.model,
                )
            except Exception as e:
                logger.error(f"Model scoring failed: {e}")
                model_score = None
                model_available = False
                model_check_status = CheckStatus.failed
                model_check_detail = f"Scoring failed: {e}"
                model_evidence = None
        else:
            model_check_status = CheckStatus.unavailable
            model_check_detail = model_error or "Model not loaded."
            model_evidence = None

        # ── 6. Reputation checks ──────────────────────────────────────────
        reputation_results: list[ReputationResult] = await check_url_reputation(
            url_input, db_session
        )

        # Add reputation evidence for matches
        rep_evidence = []
        for rep in reputation_results:
            if rep.status == "match":
                rep_evidence.append(EvidenceItem(
                    category="REPUTATION_MATCH",
                    severity=Severity.high,
                    title=f"Listed in {rep.source}",
                    detail=rep.detail or f"This URL appears in the {rep.source} threat feed.",
                    source=EvidenceSource.reputation,
                ))

        # Add parser notes as evidence
        parser_evidence = []
        for note in parsed.notes:
            parser_evidence.append(EvidenceItem(
                category="PARSER_NOTE",
                severity=Severity.info,
                title="URL parsing note",
                detail=note,
                source=EvidenceSource.parser,
            ))

        # ── 7. Decision ───────────────────────────────────────────────────
        mal_thresh = model.malicious_threshold if model else 0.95
        sus_thresh = model.suspicious_threshold if model else 0.6

        verdict = decide_verdict(
            rule_results=rule_results,
            reputation_results=reputation_results,
            model_score=model_score,
            model_available=model_available,
            malicious_threshold=mal_thresh,
            suspicious_threshold=sus_thresh,
            model_check_status=model_check_status,
        )

        display_label = make_display_label("url", verdict)

        # ── 8. Build summary ──────────────────────────────────────────────
        summary = _build_summary(verdict, rule_results, reputation_results, model_score, domain_result)

        # ── 9. Assemble evidence ──────────────────────────────────────────
        all_evidence = rep_evidence + rule_evidence + parser_evidence
        if model_evidence:
            all_evidence.append(model_evidence)

        # ── 10. Build checks ──────────────────────────────────────────────
        checks = build_checks(
            model_available=model_available,
            model_check_status=model_check_status,
            model_check_detail=model_check_detail,
            reputation_results=reputation_results,
            parser_ok=True,
            rules_ran=True,
        )

        # ── 11. Limitations and recommendations ──────────────────────────
        limitations = list(LIMITATIONS)
        if not model_available:
            limitations.insert(0, f"ML model unavailable: {model_error or 'not loaded'}. "
                                   "Using rules and reputation only.")

        recommendations = standard_recommendations(verdict)

        duration_ms = int((time.perf_counter() - t_start) * 1000)

        result = AnalysisResult(
            investigation_id=investigation_id,
            type=ModuleType.url,
            created_at=created_at,
            verdict=verdict,
            display_label=display_label,
            summary=summary,
            evidence=all_evidence,
            checks_performed=checks,
            limitations=limitations,
            recommendations=recommendations,
            analysis_version="1.0.0",
            model_version=model.model_version if model else None,
            input_summary=f"URL: {parsed.host}{parsed.path[:50] if parsed.path else ''}",
        )

        # Details for storage
        url_details = {
            "original_url": url_input,
            "registrable_domain": parsed.registrable_domain,
            "scheme": parsed.scheme,
            "host": parsed.host,
            "path": parsed.path[:500] if parsed.path else None,
            "model_score": model_score,
            "model_band": model_band_str,
            "reputation_results": [
                {"source": r.source, "status": r.status, "detail": r.detail}
                for r in reputation_results
            ],
            "rule_hits": [
                {"id": r.rule_id, "severity": r.severity.value, "title": r.title}
                for r in rule_results if r.fired
            ],
            "features_summary": {
                k: v for k, v in features.items()
                if k in {"hostname_entropy", "is_ip", "is_punycode",
                         "brand_lookalike_score", "is_shortener", "is_tunnel_host"}
            },
            "duration_ms": duration_ms,
        }

        return result, url_details


def _build_summary(
    verdict: Verdict,
    rule_results,
    reputation_results,
    model_score: Optional[float],
    domain_result,
) -> str:
    rep_matches = [r for r in reputation_results if r.status == "match"]
    fired_high = [r for r in rule_results if r.fired and r.severity.value in ("high",)]
    fired_medium = [r for r in rule_results if r.fired and r.severity.value == "medium"]

    if verdict == Verdict.malicious:
        if rep_matches:
            src = rep_matches[0].source
            return (f"This URL is listed in the {src} threat feed as malicious. "
                    "Do not open it or enter any personal information.")
        if fired_high:
            reason = fired_high[0].title.lower()
            return f"This URL shows strong warning signs ({reason}). It is very likely a phishing or scam link."
        return "This URL shows multiple strong warning signs. It is very likely malicious."

    if verdict == Verdict.suspicious:
        reasons = []
        if fired_high:
            reasons.append(fired_high[0].title.lower())
        elif fired_medium:
            reasons.append(fired_medium[0].title.lower())
        if model_score is not None and model_score > 0.4:
            reasons.append("ML model indicates elevated risk")
        reason_str = "; ".join(reasons) if reasons else "security rules indicate risk"
        return f"This URL has suspicious characteristics ({reason_str}). Exercise caution."

    if verdict == Verdict.clean_no_findings:
        return ("No known threats were detected in this URL. "
                "This is not a guarantee of safety—always verify through official channels.")

    return ("The analysis could not reach a confident verdict for this URL. "
            "Treat it with caution. Use official apps or websites instead.")
