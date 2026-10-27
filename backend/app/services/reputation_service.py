"""
Reputation service – checks URLs against threat-intelligence sources.
Each source is isolated; one failing never breaks the scan.
"""
from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Optional

import httpx

from app.config import get_settings
from app.security.risk_policy import ReputationResult

logger = logging.getLogger(__name__)


def _url_hash(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()


def _normalise_for_lookup(url: str) -> str:
    """Normalise URL for reputation lookups (lowercase scheme/host)."""
    url = url.strip()
    try:
        import urllib.parse as up
        p = up.urlparse(url)
        return up.urlunparse((
            p.scheme.lower(),
            p.netloc.lower(),
            p.path,
            p.params,
            p.query,
            "",
        ))
    except Exception:
        return url


# Simple in-memory cache: {url_hash: (result, timestamp)}
_cache: dict[str, tuple[list[ReputationResult], float]] = {}
_CACHE_TTL = 600  # 10 minutes


def _get_cached(url: str) -> Optional[list[ReputationResult]]:
    h = _url_hash(_normalise_for_lookup(url))
    if h in _cache:
        result, ts = _cache[h]
        if time.time() - ts < _CACHE_TTL:
            return result
        del _cache[h]
    return None


def _set_cached(url: str, results: list[ReputationResult]) -> None:
    h = _url_hash(_normalise_for_lookup(url))
    _cache[h] = (results, time.time())


async def _check_google_safebrowsing(url: str, api_key: str, timeout: int) -> ReputationResult:
    """Google Safe Browsing Lookup API v4."""
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    body = {
        "client": {"clientId": "phishshield", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(endpoint, json=body)
            resp.raise_for_status()
            data = resp.json()
            if data.get("matches"):
                match = data["matches"][0]
                return ReputationResult(
                    source="Google Safe Browsing",
                    status="match",
                    detail=f"Threat type: {match.get('threatType', 'unknown')}",
                    threat_type=match.get("threatType"),
                )
            return ReputationResult(source="Google Safe Browsing", status="no_match")
    except httpx.TimeoutException:
        return ReputationResult(source="Google Safe Browsing", status="error", detail="Request timed out")
    except Exception as e:
        logger.warning(f"Google Safe Browsing error: {e}")
        return ReputationResult(source="Google Safe Browsing", status="error", detail=str(e)[:100])


async def _check_urlhaus_api(url: str, timeout: int, auth_key: Optional[str] = None) -> ReputationResult:
    """URLhaus query API – checks a URL."""
    endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
    headers = {}
    if auth_key:
        headers["Auth-Key"] = auth_key
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(endpoint, data={"url": url}, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            if data.get("query_status") == "is_whitelist":
                return ReputationResult(source="URLhaus", status="no_match", detail="URL is whitelisted")
            if data.get("query_status") == "no_results":
                return ReputationResult(source="URLhaus", status="no_match")
            if data.get("url_status") in ("online", "offline"):
                return ReputationResult(
                    source="URLhaus",
                    status="match",
                    detail=f"Status: {data.get('url_status')}, "
                           f"Tags: {', '.join(data.get('tags') or [])}",
                    threat_type="malware_distribution",
                )
            return ReputationResult(source="URLhaus", status="no_match")
    except httpx.TimeoutException:
        return ReputationResult(source="URLhaus", status="error", detail="Request timed out")
    except Exception as e:
        logger.warning(f"URLhaus error: {e}")
        return ReputationResult(source="URLhaus", status="error", detail=str(e)[:100])


async def _check_local_openphish(url: str, db_session) -> ReputationResult:
    """Check local OpenPhish feed cache in SQLite."""
    try:
        from app.database.models import ReputationFeedEntry, FeedStatus
        from sqlalchemy import select
        norm_url = _normalise_for_lookup(url)
        url_hash = _url_hash(norm_url)

        # Check feed freshness
        feed_status = db_session.execute(
            select(FeedStatus).where(FeedStatus.source == "openphish")
        ).scalar_one_or_none()

        settings = get_settings()
        feed_max_age = timedelta(hours=settings.FEED_MAX_AGE_HOURS)
        is_stale = True
        if feed_status and feed_status.last_success_at:
            age = datetime.now(timezone.utc) - feed_status.last_success_at
            is_stale = age > feed_max_age

        if is_stale:
            detail = "Feed data is stale or not yet downloaded. Run scripts/refresh_feeds.py to update."
            return ReputationResult(source="OpenPhish (local)", status="stale", detail=detail)

        entry = db_session.execute(
            select(ReputationFeedEntry).where(
                ReputationFeedEntry.source == "openphish",
                ReputationFeedEntry.url_hash == url_hash,
            )
        ).scalar_one_or_none()

        if entry:
            return ReputationResult(
                source="OpenPhish (local)",
                status="match",
                detail=f"Found in OpenPhish community feed (fetched {feed_status.last_success_at.date() if feed_status else 'unknown'})",
                threat_type="phishing",
            )
        return ReputationResult(source="OpenPhish (local)", status="no_match")
    except Exception as e:
        logger.warning(f"OpenPhish local check error: {e}")
        return ReputationResult(source="OpenPhish (local)", status="error", detail=str(e)[:100])


async def check_url_reputation(
    url: str,
    db_session=None,
) -> list[ReputationResult]:
    """
    Check a URL against all configured reputation sources.
    Returns list of ReputationResult (one per source).
    """
    settings = get_settings()

    # Check cache first
    cached = _get_cached(url)
    if cached is not None:
        logger.debug(f"Reputation cache hit for URL hash")
        return cached

    results: list[ReputationResult] = []
    timeout = settings.REPUTATION_TIMEOUT_SECONDS

    if not settings.ENABLE_EXTERNAL_LOOKUPS:
        results.append(ReputationResult(
            source="Google Safe Browsing",
            status="unconfigured",
            detail="External lookups disabled. Set ENABLE_EXTERNAL_LOOKUPS=true in .env.",
        ))
        results.append(ReputationResult(
            source="URLhaus",
            status="unconfigured",
            detail="External lookups disabled.",
        ))
        results.append(ReputationResult(
            source="OpenPhish (local)",
            status="unconfigured" if db_session is None else "stale",
            detail="External lookups disabled.",
        ))
        return results

    # Google Safe Browsing
    if settings.google_safebrowsing_configured:
        results.append(await _check_google_safebrowsing(url, settings.GOOGLE_SAFE_BROWSING_API_KEY, timeout))
    else:
        results.append(ReputationResult(
            source="Google Safe Browsing",
            status="unconfigured",
            detail="GOOGLE_SAFE_BROWSING_API_KEY not set.",
        ))

    # URLhaus
    if settings.urlhaus_configured:
        results.append(await _check_urlhaus_api(url, timeout, settings.URLHAUS_AUTH_KEY or None))
    else:
        results.append(ReputationResult(
            source="URLhaus",
            status="unconfigured",
            detail="External lookups not enabled.",
        ))

    # OpenPhish (local cache)
    if db_session is not None and settings.openphish_configured:
        results.append(await _check_local_openphish(url, db_session))
    else:
        results.append(ReputationResult(
            source="OpenPhish (local)",
            status="unconfigured" if not settings.openphish_configured else "error",
            detail="No database session or OpenPhish not configured.",
        ))

    _set_cached(url, results)
    return results
