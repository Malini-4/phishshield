"""
Domain checks: brand lookalike detection, tunnel/shortener detection.
Enriches feature dict and returns evidence items.
"""
from __future__ import annotations

import csv
import logging
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).parent.parent.parent.parent / "data" / "reference"


@dataclass
class BrandEntry:
    brand: str
    category: str
    official_domains: list[str]  # registrable domains
    country: str
    source_note: str


@dataclass
class TunnelEntry:
    host_suffix: str
    kind: str
    note: str


@lru_cache(maxsize=1)
def load_brand_domains() -> list[BrandEntry]:
    """Load brand domains from CSV. Cached after first load."""
    path = _DATA_DIR / "brand_domains.csv"
    entries = []
    try:
        with open(path, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                domains = [d.strip().lower() for d in row["official_registrable_domains"].split(",") if d.strip()]
                entries.append(BrandEntry(
                    brand=row["brand"],
                    category=row["category"],
                    official_domains=domains,
                    country=row.get("country", ""),
                    source_note=row.get("source_note", ""),
                ))
    except Exception as e:
        logger.error(f"Failed to load brand domains: {e}")
    return entries


@lru_cache(maxsize=1)
def load_tunnel_hosts() -> list[TunnelEntry]:
    """Load tunnel/free-hosting hosts from CSV. Cached."""
    path = _DATA_DIR / "tunnel_hosts.csv"
    entries = []
    try:
        with open(path, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                entries.append(TunnelEntry(
                    host_suffix=row["host_suffix"].strip().lower(),
                    kind=row["kind"].strip(),
                    note=row["note"].strip(),
                ))
    except Exception as e:
        logger.error(f"Failed to load tunnel hosts: {e}")
    return entries


def _edit_distance(a: str, b: str) -> int:
    """Simple Levenshtein edit distance."""
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if la == 0:
        return lb
    if lb == 0:
        return la
    prev = list(range(lb + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(
                prev[j] + 1,
                curr[j - 1] + 1,
                prev[j - 1] + (0 if ca == cb else 1),
            ))
        prev = curr
    return prev[lb]


@dataclass
class DomainCheckResult:
    brand_lookalike_score: float  # 0.0 – 1.0 (1 = exact match official, so legitimate)
    is_official: bool  # True if registrable_domain exactly matches an official domain
    lookalike_brand: Optional[str]
    lookalike_official_domain: Optional[str]
    edit_distance: Optional[int]
    brand_in_subdomain: bool  # brand token in subdomain but registrable ≠ official
    brand_in_path: bool  # brand token in path but registrable ≠ official
    is_shortener: bool
    is_tunnel: bool
    tunnel_kind: Optional[str]
    tunnel_note: Optional[str]


def check_domain(
    registrable_domain: str,
    subdomain: str,
    path: str,
    host: str,
) -> DomainCheckResult:
    """
    Perform all domain-based checks.
    Does NOT make network calls.
    """
    brands = load_brand_domains()
    tunnels = load_tunnel_hosts()
    from app.security.url_features import SHORTENER_DOMAINS

    reg = registrable_domain.lower()
    sub = subdomain.lower()
    path_lower = path.lower()
    host_lower = host.lower()

    # ── 1. Official domain exact match ──────────────────────────────────────
    for entry in brands:
        if reg in entry.official_domains:
            return DomainCheckResult(
                brand_lookalike_score=1.0,
                is_official=True,
                lookalike_brand=entry.brand,
                lookalike_official_domain=reg,
                edit_distance=0,
                brand_in_subdomain=False,
                brand_in_path=False,
                is_shortener=reg in SHORTENER_DOMAINS,
                is_tunnel=False,
                tunnel_kind=None,
                tunnel_note=None,
            )

    # ── 2. Lookalike / typosquat detection ──────────────────────────────────
    try:
        reg_decoded = reg.encode("ascii").decode("idna")
    except Exception:
        reg_decoded = reg

    best_score = 0.0
    best_brand: Optional[str] = None
    best_official: Optional[str] = None
    best_dist: Optional[int] = None

    for entry in brands:
        for official in entry.official_domains:
            for candidate in {reg, reg_decoded}:
                dist = _edit_distance(candidate, official)
                max_len = max(len(candidate), len(official), 1)
                sim = 1.0 - (dist / max_len)
                if sim > best_score and sim < 1.0:  # < 1.0 excludes exact match
                    best_score = sim
                    best_brand = entry.brand
                    best_official = official
                    best_dist = dist

    # ── 3. Brand token in subdomain/path ────────────────────────────────────
    brand_in_sub = False
    brand_in_path_flag = False
    for entry in brands:
        brand_lower = entry.brand.lower().replace(" ", "")
        alt_names = [brand_lower]
        # add first word of multi-word brands
        words = entry.brand.lower().split()
        if words:
            alt_names.append(words[0])

        for token in alt_names:
            if len(token) < 3:
                continue
            if token in sub and reg not in entry.official_domains:
                brand_in_sub = True
            if token in path_lower and reg not in entry.official_domains:
                brand_in_path_flag = True

    # ── 4. Shortener check ──────────────────────────────────────────────────
    is_short = reg in SHORTENER_DOMAINS

    # ── 5. Tunnel / free-hosting check ──────────────────────────────────────
    is_tunnel = False
    tunnel_kind = None
    tunnel_note = None
    for t in tunnels:
        if host_lower.endswith("." + t.host_suffix) or host_lower == t.host_suffix:
            is_tunnel = True
            tunnel_kind = t.kind
            tunnel_note = t.note
            break

    return DomainCheckResult(
        brand_lookalike_score=best_score,
        is_official=False,
        lookalike_brand=best_brand,
        lookalike_official_domain=best_official,
        edit_distance=best_dist,
        brand_in_subdomain=brand_in_sub,
        brand_in_path=brand_in_path_flag,
        is_shortener=is_short,
        is_tunnel=is_tunnel,
        tunnel_kind=tunnel_kind,
        tunnel_note=tunnel_note,
    )


def enrich_features(features: dict, domain_result: DomainCheckResult) -> dict:
    """Update feature dict with brand/tunnel/shortener results."""
    features = dict(features)
    # For ML: use complement score (how similar to a brand, but not official)
    if domain_result.is_official:
        features["brand_lookalike_score"] = 0.0  # official = not a lookalike threat
    else:
        features["brand_lookalike_score"] = domain_result.brand_lookalike_score
    features["brand_in_subdomain_not_registrable"] = float(domain_result.brand_in_subdomain)
    features["brand_in_path_not_registrable"] = float(domain_result.brand_in_path)
    features["is_shortener"] = float(domain_result.is_shortener)
    features["is_tunnel_host"] = float(domain_result.is_tunnel)
    return features
