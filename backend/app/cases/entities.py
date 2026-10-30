"""Entity extraction and linkability assessment for case correlation."""
from __future__ import annotations

import csv
import ipaddress
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from app.security.url_parser import parse_url

_DATA_DIR = Path(__file__).parent.parent.parent.parent / "data" / "reference"

BENIGN_MAJOR_DOMAINS: Set[str] = {
    "google.com", "google.co.in", "apple.com", "microsoft.com", "android.com",
    "whatsapp.com", "facebook.com", "instagram.com", "telegram.org", "twitter.com",
    "x.com", "youtube.com", "github.com", "cloudflare.com", "play.google.com"
}

LINK_SHORTENERS: Set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
    "rb.gy", "shorturl.at", "ow.ly", "buff.ly", "rebrand.ly", "tiny.cc"
}


@lru_cache(maxsize=1)
def load_official_bank_domains() -> Set[str]:
    """Load domains from brand_domains.csv."""
    path = _DATA_DIR / "brand_domains.csv"
    domains: Set[str] = set()
    if not path.exists():
        return domains
    try:
        with open(path, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                d = (row.get("domain") or "").strip().lower()
                if d:
                    domains.add(d)
    except Exception:
        pass
    return domains


@lru_cache(maxsize=1)
def load_verified_sender_headers() -> Set[str]:
    """Load headers from sms_sender_reference.csv."""
    path = _DATA_DIR / "sms_sender_reference.csv"
    headers: Set[str] = set()
    if not path.exists():
        return headers
    try:
        with open(path, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                h = (row.get("header") or "").strip().upper()
                if h:
                    headers.add(h)
    except Exception:
        pass
    return headers


def is_benign_domain(domain: str) -> bool:
    d = domain.lower().strip()
    if d in BENIGN_MAJOR_DOMAINS:
        return True
    if d in LINK_SHORTENERS:
        return True
    if d in load_official_bank_domains():
        return True
    # check subdomains of benign major domains
    for benign in BENIGN_MAJOR_DOMAINS:
        if d.endswith("." + benign):
            return True
    for bank_dom in load_official_bank_domains():
        if d.endswith("." + bank_dom):
            return True
    return False


def is_link_shortener(domain: str) -> bool:
    d = domain.lower().strip()
    return d in LINK_SHORTENERS or any(d.endswith("." + ls) for ls in LINK_SHORTENERS)


def is_verified_sender(sender: str) -> bool:
    s = sender.upper().strip()
    from app.services.sms_text import split_sender
    core = split_sender(s)
    verified = load_verified_sender_headers()
    return s in verified or core in verified or (len(core) == 8 and core[2:] in verified)


def extract_entities(
    module_type: str,
    verdict: str,
    input_display: str,
    result_dict: Dict[str, Any],
    details_dict: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    Extract shared clues (entities) from an investigation.
    Returns list of {"entity_type": str, "entity_value": str, "linkable": bool}.
    """
    entities: List[Dict[str, Any]] = []
    seen: Set[tuple[str, str]] = set()

    def add_entity(etype: str, evalue: str, linkable: bool):
        val = evalue.strip()
        if not val:
            return
        # Normalize
        if etype in ("domain", "url", "apk_package", "apk_sha256", "cert_sha256", "file_sha256", "upi_id"):
            val = val.lower()
        if etype == "sender_id":
            val = val.upper()
        key = (etype, val)
        if key not in seen:
            seen.add(key)
            entities.append({
                "entity_type": etype,
                "entity_value": val,
                "linkable": bool(linkable),
            })

    is_suspicious_or_malicious = verdict in ("suspicious", "malicious")
    details = details_dict or {}

    # 1. URL Analysis
    if module_type == "url":
        url = input_display
        try:
            parsed = parse_url(url)
            if hasattr(parsed, "normalised"):
                linkable_url = is_suspicious_or_malicious and not is_benign_domain(parsed.registrable_domain or parsed.host)
                add_entity("url", parsed.normalised, linkable_url)
                if parsed.registrable_domain:
                    linkable_dom = is_suspicious_or_malicious and not is_benign_domain(parsed.registrable_domain)
                    add_entity("domain", parsed.registrable_domain, linkable_dom)
                if parsed.is_ip and parsed.ip_address:
                    add_entity("ip", parsed.ip_address, is_suspicious_or_malicious)
        except Exception:
            pass

    # 2. SMS Analysis
    elif module_type == "sms":
        text = details.get("redacted_text") or input_display
        sender = details.get("sender")
        if sender:
            # Verified brand sender headers are not linkable
            linkable_sender = not is_verified_sender(sender)
            add_entity("sender_id", sender, linkable_sender)

        # Phone numbers inside text (10-digit Indian mobiles)
        phone_matches = re.findall(r"(?:(?:\+?91[\s\-]?)?([6-9]\d{9}))", text)
        for ph in phone_matches:
            add_entity("phone", ph, True)

        # UPI IDs in text
        upi_matches = re.findall(r"\b([a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64})\b", text)
        for upi in upi_matches:
            add_entity("upi_id", upi, True)

        # URLs in text
        urls = details.get("extracted_urls", [])
        for u in urls:
            if u != "[obfuscated-shortener]":
                try:
                    parsed = parse_url(u)
                    if hasattr(parsed, "registrable_domain") and parsed.registrable_domain:
                        dom = parsed.registrable_domain
                        linkable_dom = is_suspicious_or_malicious and not is_benign_domain(dom)
                        add_entity("domain", dom, linkable_dom)
                        linkable_url = is_suspicious_or_malicious and not is_benign_domain(dom)
                        add_entity("url", parsed.normalised, linkable_url)
                except Exception:
                    pass

    # 3. APK Analysis
    elif module_type == "apk":
        pkg = details.get("package_name")
        if pkg:
            linkable_pkg = is_suspicious_or_malicious
            add_entity("apk_package", pkg, linkable_pkg)

        apk_hash = details.get("sha256")
        if apk_hash:
            add_entity("apk_sha256", apk_hash, True)
            add_entity("file_sha256", apk_hash, True)

        for cert in details.get("certificates", []):
            if cert:
                linkable_cert = is_suspicious_or_malicious
                add_entity("cert_sha256", cert, linkable_cert)

    # 4. Screenshot Analysis
    elif module_type == "screenshot":
        file_hash = details.get("file_hash")
        if file_hash:
            add_entity("file_sha256", file_hash, True)

        fields = details.get("extracted_fields", {})
        upi_id = (fields.get("upi_id") or {}).get("value")
        if upi_id:
            add_entity("upi_id", upi_id, True)

        utr = (fields.get("utr") or {}).get("value")
        if utr and str(utr).isdigit() and len(str(utr)) == 12:
            add_entity("utr", str(utr), True)

    return entities
