"""
URL security rules – deterministic, documented, unit-tested.
Each rule has: id, description, severity, rationale.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from app.schemas.shared import EvidenceItem, EvidenceSource, Severity
from app.security.url_parser import ParsedUrl
from app.security.domain_checks import DomainCheckResult


@dataclass
class RuleResult:
    rule_id: str
    fired: bool
    severity: Severity
    title: str
    detail: str


# ── Individual rule functions ────────────────────────────────────────────────

def rule_ip_host(parsed: ParsedUrl) -> RuleResult:
    """
    IP_HOST: host is an IP address (any encoding).
    Severity: medium (not high alone; internal/dev tools exist).
    Negative test: 192.168.1.1 (internal) → medium, not auto-malicious.
    Positive test: http://3232235777/login → fires.
    """
    if parsed.is_ip:
        form_desc = f" (encoded as {parsed.ip_form})" if parsed.ip_form else ""
        return RuleResult(
            rule_id="IP_HOST",
            fired=True,
            severity=Severity.medium,
            title="IP address used as host",
            detail=f"The URL uses an IP address{form_desc} instead of a domain name. "
                   "Legitimate websites almost never use raw IPs in links shared with users.",
        )
    return RuleResult("IP_HOST", False, Severity.medium, "", "")


def rule_ip_obfuscation(parsed: ParsedUrl) -> RuleResult:
    """
    IP_OBFUSCATION: IP encoded in hex, octal or packed decimal.
    Severity: high – no legitimate use case.
    """
    if parsed.is_ip and parsed.ip_form in ("hex", "octal", "decimal_packed", "mixed_base"):
        return RuleResult(
            rule_id="IP_OBFUSCATION",
            fired=True,
            severity=Severity.high,
            title="Obfuscated IP address detected",
            detail=f"The IP address is encoded in {parsed.ip_form} form, "
                   "a technique used to disguise the destination.",
        )
    return RuleResult("IP_OBFUSCATION", False, Severity.high, "", "")


def rule_userinfo_trick(parsed: ParsedUrl) -> RuleResult:
    """
    USERINFO_TRICK: @ in URL authority where the left side looks like a domain.
    E.g. http://www.legitbank.com@evil.com/path
    Severity: high.
    Positive: http://sbi.co.in@attacker.com/login
    Negative: user@hostname-that-is-not-a-domain (less suspicious but still flagged).
    """
    if parsed.userinfo:
        ui = parsed.userinfo
        # Check if userinfo looks like a domain (contains a dot and is not just user:pass)
        looks_like_domain = "." in ui.split(":")[0]
        sev = Severity.high if looks_like_domain else Severity.medium
        return RuleResult(
            rule_id="USERINFO_TRICK",
            fired=True,
            severity=sev,
            title="Userinfo (@) in URL – possible deceptive domain",
            detail=f"The URL contains '{ui}@' before the real host. "
                   "This is a common trick to make a phishing URL appear to be from a trusted site. "
                   "The actual destination is the domain after '@'.",
        )
    return RuleResult("USERINFO_TRICK", False, Severity.high, "", "")


def rule_punycode_lookalike(parsed: ParsedUrl, domain_result: DomainCheckResult) -> RuleResult:
    """
    PUNYCODE_BRAND_LOOKALIKE: IDN/punycode hostname confusable with a known brand.
    Severity: high.
    """
    if parsed.is_idna and not domain_result.is_official and domain_result.brand_lookalike_score > 0.75:
        return RuleResult(
            rule_id="PUNYCODE_BRAND_LOOKALIKE",
            fired=True,
            severity=Severity.high,
            title="Internationalised domain looks like a known brand",
            detail=f"This domain uses internationalised characters (Punycode) and resembles "
                   f"'{domain_result.lookalike_brand}' ({domain_result.lookalike_official_domain}). "
                   "This is a known technique to create visually deceptive URLs.",
        )
    return RuleResult("PUNYCODE_BRAND_LOOKALIKE", False, Severity.high, "", "")


def rule_brand_in_subdomain(parsed: ParsedUrl, domain_result: DomainCheckResult) -> RuleResult:
    """
    BRAND_IN_SUBDOMAIN_OR_PATH_NOT_REGISTRABLE: brand name appears in subdomain or path
    but registrable domain is not the official one.
    Severity: medium/high based on edit distance of registrable domain.
    Positive: hdfc.secure-login.xyz/netbanking
    Negative: netbanking.hdfcbank.com/login → is_official=True, not fired.
    """
    if domain_result.brand_in_subdomain and not domain_result.is_official:
        sev = Severity.high if domain_result.brand_lookalike_score > 0.5 else Severity.medium
        return RuleResult(
            rule_id="BRAND_IN_SUBDOMAIN_NOT_REGISTRABLE",
            fired=True,
            severity=sev,
            title="Brand name in subdomain but not on official domain",
            detail=f"The URL contains a recognised brand name in the subdomain "
                   f"but the actual domain ({parsed.registrable_domain}) is not the official one. "
                   "This is a common impersonation pattern.",
        )
    return RuleResult("BRAND_IN_SUBDOMAIN_NOT_REGISTRABLE", False, Severity.high, "", "")


def rule_brand_in_path(parsed: ParsedUrl, domain_result: DomainCheckResult) -> RuleResult:
    """
    BRAND_IN_PATH_NOT_REGISTRABLE: brand token in path but registrable ≠ official.
    Severity: medium.
    """
    if domain_result.brand_in_path and not domain_result.is_official:
        return RuleResult(
            rule_id="BRAND_IN_PATH_NOT_REGISTRABLE",
            fired=True,
            severity=Severity.medium,
            title="Brand name in URL path but not on official domain",
            detail=f"A recognised brand name appears in the URL path, "
                   f"but the domain ({parsed.registrable_domain}) is not the official one.",
        )
    return RuleResult("BRAND_IN_PATH_NOT_REGISTRABLE", False, Severity.medium, "", "")


def rule_typosquat(parsed: ParsedUrl, domain_result: DomainCheckResult) -> RuleResult:
    """
    TYPOSQUAT: registrable domain within small edit distance of known brand but not equal.
    Severity: medium (dist=1) or high (if also has brand token).
    Positive: hdfcbonk.com (dist 1 from hdfcbank.com) → fires.
    Negative: hdfcbank.com → is_official=True, not fired.
    """
    if (not domain_result.is_official
            and domain_result.edit_distance is not None
            and 0 < domain_result.edit_distance <= 2
            and domain_result.brand_lookalike_score > 0.8):
        sev = Severity.high if domain_result.edit_distance == 1 else Severity.medium
        return RuleResult(
            rule_id="TYPOSQUAT",
            fired=True,
            severity=sev,
            title=f"Possible typosquatting of '{domain_result.lookalike_brand}'",
            detail=f"The domain '{parsed.registrable_domain}' is very similar to "
                   f"'{domain_result.lookalike_official_domain}' (edit distance: {domain_result.edit_distance}). "
                   "This may be a typosquatting attack.",
        )
    return RuleResult("TYPOSQUAT", False, Severity.high, "", "")


def rule_shortener(domain_result: DomainCheckResult) -> RuleResult:
    """
    SHORTENER: known URL shortener hides the real destination.
    Severity: low/medium.
    """
    if domain_result.is_shortener:
        return RuleResult(
            rule_id="SHORTENER",
            fired=True,
            severity=Severity.low,
            title="URL shortener detected",
            detail="This is a shortened URL. The real destination is hidden and cannot be analysed without resolving it. "
                   "Be cautious before opening shortened links from unknown sources.",
        )
    return RuleResult("SHORTENER", False, Severity.low, "", "")


def rule_tunnel_host(parsed: ParsedUrl, domain_result: DomainCheckResult) -> RuleResult:
    """
    TUNNEL_OR_FREE_HOSTING: host is a known tunnel or free-hosting service.
    Severity: info (supporting evidence only; most use is legitimate).
    """
    if domain_result.is_tunnel:
        return RuleResult(
            rule_id="TUNNEL_OR_FREE_HOSTING",
            fired=True,
            severity=Severity.info,
            title=f"Tunnel or free-hosting service detected ({domain_result.tunnel_kind})",
            detail=f"The URL uses a {domain_result.tunnel_kind} service ({parsed.host}). "
                   "While most such usage is legitimate, phishing kits are sometimes served this way. "
                   "Combined with other signals, this may indicate risk.",
        )
    return RuleResult("TUNNEL_OR_FREE_HOSTING", False, Severity.info, "", "")


def rule_excessive_subdomains(parsed: ParsedUrl) -> RuleResult:
    """
    EXCESSIVE_SUBDOMAINS: host has 4+ subdomain levels.
    Severity: low.
    """
    labels = [l for l in parsed.host.split(".") if l]
    num_sub = max(0, len(labels) - 2)
    if num_sub >= 4:
        return RuleResult(
            rule_id="EXCESSIVE_SUBDOMAINS",
            fired=True,
            severity=Severity.low,
            title=f"Unusual number of subdomains ({num_sub})",
            detail=f"The hostname has {num_sub} subdomain levels, which is uncommon for legitimate services.",
        )
    return RuleResult("EXCESSIVE_SUBDOMAINS", False, Severity.low, "", "")


def rule_long_random_host(parsed: ParsedUrl) -> RuleResult:
    """
    LONG_RANDOM_HOST: very high hostname entropy → likely randomly generated.
    Severity: medium.
    """
    import math
    host = parsed.host
    if not host:
        return RuleResult("LONG_RANDOM_HOST", False, Severity.medium, "", "")
    # Entropy calculation
    freq = {}
    for c in host.replace(".", ""):
        freq[c] = freq.get(c, 0) + 1
    n = len(host.replace(".", ""))
    if n == 0:
        return RuleResult("LONG_RANDOM_HOST", False, Severity.medium, "", "")
    entropy = -sum((v / n) * math.log2(v / n) for v in freq.values())
    if entropy > 4.2 and len(host) > 20:
        return RuleResult(
            rule_id="LONG_RANDOM_HOST",
            fired=True,
            severity=Severity.medium,
            title="High-entropy hostname (possibly generated)",
            detail=f"The hostname has unusually high randomness (entropy: {entropy:.2f}), "
                   "suggesting it may have been automatically generated.",
        )
    return RuleResult("LONG_RANDOM_HOST", False, Severity.medium, "", "")


def rule_nonstandard_port(parsed: ParsedUrl) -> RuleResult:
    """
    NONSTANDARD_PORT: non-standard HTTP/HTTPS port.
    Severity: low.
    Negative: :443 on https, :80 on http → not fired.
    """
    standard = {None, 80, 443}
    if parsed.port not in standard:
        return RuleResult(
            rule_id="NONSTANDARD_PORT",
            fired=True,
            severity=Severity.low,
            title=f"Non-standard port used (:{parsed.port})",
            detail=f"The URL uses port {parsed.port} instead of the standard port. "
                   "This is unusual for links shared with general users.",
        )
    return RuleResult("NONSTANDARD_PORT", False, Severity.low, "", "")


def rule_embedded_redirect(parsed: ParsedUrl) -> RuleResult:
    """
    EMBEDDED_REDIRECT_URL: query contains a redirect/url parameter with an http value.
    Severity: medium.
    """
    import urllib.parse as up
    if not parsed.query:
        return RuleResult("EMBEDDED_REDIRECT_URL", False, Severity.medium, "", "")
    REDIRECT_PARAMS = {
        "url", "redirect", "redirect_url", "redir", "return",
        "return_url", "next", "goto", "destination", "continue",
        "target", "link", "out", "go",
    }
    params = up.parse_qs(parsed.query)
    for k, vals in params.items():
        if k.lower() in REDIRECT_PARAMS:
            for v in vals:
                if v.lower().startswith("http"):
                    return RuleResult(
                        rule_id="EMBEDDED_REDIRECT_URL",
                        fired=True,
                        severity=Severity.medium,
                        title="Open redirect parameter detected",
                        detail=f"The URL contains a redirect parameter ('{k}') pointing to another URL. "
                               "This can be used to redirect users to malicious destinations.",
                    )
    return RuleResult("EMBEDDED_REDIRECT_URL", False, Severity.medium, "", "")


def rule_double_encoding(parsed: ParsedUrl) -> RuleResult:
    """
    DOUBLE_ENCODING: double percent-encoding detected.
    Severity: medium.
    """
    if parsed.double_encoding_detected:
        return RuleResult(
            rule_id="DOUBLE_ENCODING",
            fired=True,
            severity=Severity.medium,
            title="Double URL encoding detected",
            detail="The URL contains double percent-encoding (%25xx), which can be used to bypass filters.",
        )
    return RuleResult("DOUBLE_ENCODING", False, Severity.medium, "", "")


def rule_executable_extension(parsed: ParsedUrl) -> RuleResult:
    """
    EXECUTABLE_DOWNLOAD_EXT: URL path ends with a dangerous file extension.
    Severity: medium.
    """
    from pathlib import Path as P
    DANGEROUS_EXTS = {".exe", ".apk", ".bat", ".cmd", ".ps1", ".msi",
                      ".vbs", ".scr", ".jar", ".dmg"}
    path = parsed.path.split("?")[0] if parsed.path else ""
    ext = P(path).suffix.lower()
    if ext in DANGEROUS_EXTS:
        return RuleResult(
            rule_id="EXECUTABLE_DOWNLOAD_EXT",
            fired=True,
            severity=Severity.medium,
            title=f"URL points to a potentially dangerous file ({ext})",
            detail=f"The URL appears to link to a '{ext}' file. "
                   "Never download and run files from untrusted links.",
        )
    return RuleResult("EXECUTABLE_DOWNLOAD_EXT", False, Severity.medium, "", "")


def rule_mixed_script(parsed: ParsedUrl) -> RuleResult:
    """
    MIXED_SCRIPT: hostname mixes multiple Unicode scripts.
    Severity: high – strong homograph indicator.
    """
    if parsed.is_mixed_script:
        return RuleResult(
            rule_id="MIXED_SCRIPT",
            fired=True,
            severity=Severity.high,
            title="Mixed-script characters in hostname",
            detail="The hostname mixes characters from different writing systems (e.g., Latin and Cyrillic). "
                   "This is a homograph attack technique to make a URL visually indistinguishable from a trusted one.",
        )
    return RuleResult("MIXED_SCRIPT", False, Severity.high, "", "")


# ── Rule runner ──────────────────────────────────────────────────────────────

def run_url_rules(
    parsed: ParsedUrl,
    domain_result: DomainCheckResult,
) -> list[RuleResult]:
    """Run all URL rules and return results (both fired and not)."""
    return [
        rule_ip_host(parsed),
        rule_ip_obfuscation(parsed),
        rule_userinfo_trick(parsed),
        rule_mixed_script(parsed),
        rule_punycode_lookalike(parsed, domain_result),
        rule_brand_in_subdomain(parsed, domain_result),
        rule_brand_in_path(parsed, domain_result),
        rule_typosquat(parsed, domain_result),
        rule_shortener(domain_result),
        rule_tunnel_host(parsed, domain_result),
        rule_excessive_subdomains(parsed),
        rule_long_random_host(parsed),
        rule_nonstandard_port(parsed),
        rule_embedded_redirect(parsed),
        rule_double_encoding(parsed),
        rule_executable_extension(parsed),
    ]


def fired_to_evidence(rule_results: list[RuleResult]) -> list[EvidenceItem]:
    """Convert fired rules to EvidenceItem list."""
    items = []
    for r in rule_results:
        if r.fired:
            items.append(EvidenceItem(
                category=r.rule_id,
                severity=r.severity,
                title=r.title,
                detail=r.detail,
                source=EvidenceSource.rule,
            ))
    return items
