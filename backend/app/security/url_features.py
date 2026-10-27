"""
URL Feature Extraction – shared between ML training and live inference.
FEATURE_NAMES is the authoritative ordered list; mismatch → model refused.
"""
from __future__ import annotations

import base64
import math
import re
import unicodedata
import urllib.parse
from pathlib import Path
from typing import Optional

# Lazy import of ParsedUrl to avoid circular imports
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from app.security.url_parser import ParsedUrl

# ── Suspicious tokens ────────────────────────────────────────────────────────
SUSPICIOUS_TOKENS = {
    "login", "signin", "sign-in", "logon", "log-in",
    "verify", "verification", "verifyaccount", "verifyid",
    "secure", "security", "secured",
    "update", "updateinfo", "updateaccount",
    "kyc", "kycupdate", "kycverification",
    "bank", "banking", "netbanking",
    "account", "accounts", "myaccount",
    "wallet", "ewallet", "paywallet",
    "refund", "cashback", "reward", "rewards", "prize",
    "otp", "2fa", "authenticate", "auth",
    "password", "passwd", "recover", "recovery", "reset",
    "confirm", "confirmation",
    "support", "helpdesk", "customer",
    "urgent", "important", "notice", "alert",
    "suspended", "blocked", "frozen", "deactivated",
    "payment", "pay", "upi", "imps", "neft", "rtgs",
    "invest", "profit", "earn",
}

# Known URL shorteners (registrable domains)
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co",
    "is.gd", "buff.ly", "adf.ly", "tr.im", "short.io",
    "rb.gy", "cutt.ly", "tiny.cc", "shorturl.at", "clck.ru",
    "bl.ink", "snip.ly", "rebrand.ly", "soo.gd", "yourls.org",
    "v.gd", "shrtco.de", "urlzs.com",
}

# Suspicious file extensions in path
SUSPICIOUS_EXTENSIONS = {".exe", ".apk", ".bat", ".cmd", ".ps1", ".msi",
                          ".vbs", ".scr", ".jar", ".dmg", ".zip", ".rar",
                          ".7z", ".php", ".asp", ".aspx"}

REDIRECT_PARAMS = {
    "url", "redirect", "redirect_url", "redir", "return",
    "return_url", "next", "goto", "destination", "continue",
    "target", "link", "out", "go",
}


def _entropy(s: str) -> float:
    """Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def _count_digits(s: str) -> int:
    return sum(1 for c in s if c.isdigit())


def _count_letters(s: str) -> int:
    return sum(1 for c in s if c.isalpha())


def _count_special(s: str) -> int:
    return sum(1 for c in s if not c.isalnum() and c not in ".-_")


def _longest_label(hostname: str) -> int:
    if not hostname:
        return 0
    return max(len(l) for l in hostname.split(".") if l)


def _has_base64_blob(s: str) -> bool:
    """Detect base64-like blobs of length >= 20 chars."""
    pattern = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
    for m in pattern.finditer(s):
        blob = m.group()
        # Rough entropy check
        if _entropy(blob) > 4.0:
            return True
    return False


def _has_hex_blob(s: str) -> bool:
    """Detect long hex sequences (possible obfuscation)."""
    return bool(re.search(r"[0-9a-fA-F]{32,}", s))


def _has_embedded_redirect(query: str) -> bool:
    """Detect redirect/url parameters in query string."""
    if not query:
        return False
    params = urllib.parse.parse_qs(query, keep_blank_values=True)
    for k in params:
        if k.lower() in REDIRECT_PARAMS:
            for v in params[k]:
                if v.lower().startswith("http"):
                    return True
    return False


def _suspicious_token_count(text: str) -> int:
    """Count suspicious tokens in a normalised text."""
    text_lower = text.lower()
    return sum(1 for t in SUSPICIOUS_TOKENS if t in text_lower)


def _tld_risk_group(suffix: str) -> int:
    """
    Rough TLD risk grouping:
    0 = common/low-risk (.com, .org, .net, .gov, .edu, .in, .co.in, .co.uk, etc.)
    1 = moderate (.info, .biz, .name, .mobi)
    2 = higher-risk based on PhishTank/abuse stats (.xyz, .top, .work, .click, .loan, etc.)
    """
    low_risk = {"com", "org", "net", "gov", "edu", "in", "co.in", "gov.in", "co.uk",
                "uk", "us", "ca", "au", "de", "fr", "jp", "io", "app", "dev",
                "nic.in", "ac.in", "mil", "int", "eu", "nz", "sg"}
    high_risk = {"xyz", "top", "work", "click", "loan", "win", "racing", "faith",
                 "date", "party", "review", "science", "trade", "accountant",
                 "gq", "tk", "ml", "cf", "ga", "pw", "cc", "men", "stream",
                 "download", "bid", "cricket", "link", "zip"}
    s = (suffix or "").lower()
    if s in low_risk:
        return 0
    elif s in high_risk:
        return 2
    return 1


def _path_depth(path: str) -> int:
    if not path or path == "/":
        return 0
    return len([p for p in path.split("/") if p])


# ── Main feature extraction ──────────────────────────────────────────────────

FEATURE_NAMES: list[str] = [
    # Lengths
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "longest_label_length",
    # Character counts
    "digit_count_host",
    "letter_count_host",
    "special_count_host",
    "digit_ratio_host",
    "digit_count_path",
    "special_count_url",
    # Entropy
    "hostname_entropy",
    "path_entropy",
    # Host features
    "is_ip",
    "ip_is_hex_or_octal",
    "num_subdomains",
    "subdomain_depth",
    "tld_risk_group",
    "tld_is_common",
    "hyphen_count_host",
    "is_punycode",
    "is_mixed_script",
    "has_nonstandard_port",
    "has_userinfo_at",
    "longest_label_length_host",
    # Path/Query features
    "path_depth",
    "num_query_params",
    "longest_param_value_length",
    "has_base64_blob",
    "has_hex_blob",
    "has_suspicious_extension",
    "has_embedded_redirect",
    "double_slash_in_path",
    "encoded_char_ratio_url",
    "double_encoding",
    # Lexical
    "suspicious_token_count_host",
    "suspicious_token_count_path",
    "suspicious_token_count_query",
    # Brand/lookalike – these are set to 0 here; updated by domain_checks.py
    "brand_lookalike_score",
    "brand_in_subdomain_not_registrable",
    "brand_in_path_not_registrable",
    "is_shortener",
    "is_tunnel_host",
]


def extract_features(parsed: "ParsedUrl") -> dict[str, float]:
    """
    Extract all ML features from a ParsedUrl.
    Returns a dict keyed by FEATURE_NAMES.
    Brand/tunnel features default to 0 here; enriched by domain_checks.
    """
    url = parsed.normalised
    host = parsed.host or ""
    path = parsed.path or ""
    query = parsed.query or ""
    subdomain = parsed.subdomain or ""

    # URL lengths
    url_length = float(len(url))
    hostname_length = float(len(host))
    path_length = float(len(path))
    query_length = float(len(query))
    longest_label = float(_longest_label(host))

    # Char counts
    digit_count_host = float(_count_digits(host))
    letter_count_host = float(_count_letters(host))
    special_count_host = float(_count_special(host))
    digit_ratio_host = digit_count_host / max(hostname_length, 1)
    digit_count_path = float(_count_digits(path))
    special_count_url = float(_count_special(url))

    # Entropy
    hostname_entropy = _entropy(host)
    path_entropy = _entropy(path) if path else 0.0

    # Host features
    is_ip_f = float(parsed.is_ip)
    ip_is_hex_or_octal = float(
        parsed.ip_form in ("hex", "octal", "decimal_packed", "mixed_base")
        if parsed.is_ip else False
    )

    labels = [l for l in host.split(".") if l]
    num_subdomains = float(max(0, len(labels) - 2)) if not parsed.is_ip else 0.0
    subdomain_depth = float(len([l for l in subdomain.split(".") if l])) if subdomain else 0.0

    tld_risk = float(_tld_risk_group(parsed.suffix))
    tld_is_common = float(tld_risk == 0)

    hyphen_count_host = float(host.count("-"))
    is_punycode = float(parsed.is_idna)
    is_mixed = float(parsed.is_mixed_script)

    # Port
    standard_ports = {None, 80, 443}
    has_nonstandard_port = float(parsed.port not in standard_ports)

    has_userinfo = float(parsed.userinfo is not None)
    longest_label_host = float(_longest_label(host))

    # Path / Query
    path_depth_f = float(_path_depth(path))
    params = urllib.parse.parse_qs(query) if query else {}
    num_params = float(len(params))
    longest_param = max(
        (len(v[0]) for v in params.values() if v), default=0
    )
    longest_param_f = float(longest_param)

    has_b64 = float(_has_base64_blob(path + query))
    has_hex = float(_has_hex_blob(path + query))

    ext = Path(path.split("?")[0]).suffix.lower() if path else ""
    has_susp_ext = float(ext in SUSPICIOUS_EXTENSIONS)

    has_redirect = float(_has_embedded_redirect(query))

    double_slash_in_path = float("//" in path)

    # Percent-encoding ratio
    encoded_chars = len(re.findall(r"%[0-9a-fA-F]{2}", url))
    encoded_char_ratio = float(encoded_chars) / max(len(url), 1)

    double_enc = float(parsed.double_encoding_detected)

    # Suspicious token counts
    st_host = float(_suspicious_token_count(host))
    st_path = float(_suspicious_token_count(path))
    st_query = float(_suspicious_token_count(query))

    features = {
        "url_length": url_length,
        "hostname_length": hostname_length,
        "path_length": path_length,
        "query_length": query_length,
        "longest_label_length": longest_label,
        "digit_count_host": digit_count_host,
        "letter_count_host": letter_count_host,
        "special_count_host": special_count_host,
        "digit_ratio_host": digit_ratio_host,
        "digit_count_path": digit_count_path,
        "special_count_url": special_count_url,
        "hostname_entropy": hostname_entropy,
        "path_entropy": path_entropy,
        "is_ip": is_ip_f,
        "ip_is_hex_or_octal": ip_is_hex_or_octal,
        "num_subdomains": num_subdomains,
        "subdomain_depth": subdomain_depth,
        "tld_risk_group": tld_risk,
        "tld_is_common": tld_is_common,
        "hyphen_count_host": hyphen_count_host,
        "is_punycode": is_punycode,
        "is_mixed_script": is_mixed,
        "has_nonstandard_port": has_nonstandard_port,
        "has_userinfo_at": has_userinfo,
        "longest_label_length_host": longest_label_host,
        "path_depth": path_depth_f,
        "num_query_params": num_params,
        "longest_param_value_length": longest_param_f,
        "has_base64_blob": has_b64,
        "has_hex_blob": has_hex,
        "has_suspicious_extension": has_susp_ext,
        "has_embedded_redirect": has_redirect,
        "double_slash_in_path": double_slash_in_path,
        "encoded_char_ratio_url": encoded_char_ratio,
        "double_encoding": double_enc,
        "suspicious_token_count_host": st_host,
        "suspicious_token_count_path": st_path,
        "suspicious_token_count_query": st_query,
        # Brand features – populated by domain_checks.py
        "brand_lookalike_score": 0.0,
        "brand_in_subdomain_not_registrable": 0.0,
        "brand_in_path_not_registrable": 0.0,
        "is_shortener": 0.0,
        "is_tunnel_host": 0.0,
    }

    # Validate all FEATURE_NAMES present
    assert set(features.keys()) == set(FEATURE_NAMES), (
        f"Feature mismatch: {set(FEATURE_NAMES) - set(features.keys())}"
    )

    return features


def features_to_vector(features: dict[str, float]) -> list[float]:
    """Return features in FEATURE_NAMES order as a list."""
    return [features[name] for name in FEATURE_NAMES]
