"""
Unit tests for URL Security Rules.
Ensures positive and negative test cases for each rule and guarantees legitimate login URLs are not flagged.
"""
import pytest
from app.security.url_parser import parse_url
from app.security.domain_checks import check_domain
from app.security.url_rules import (
    run_url_rules,
    rule_ip_host,
    rule_userinfo_trick,
    rule_punycode_lookalike,
    rule_brand_in_subdomain,
    rule_typosquat,
    rule_shortener,
    rule_tunnel_host,
    rule_embedded_redirect,
)
from app.schemas.shared import Severity


def test_ip_host_rule():
    # Positive
    p_pos = parse_url("http://192.168.1.1/test")
    r_pos = rule_ip_host(p_pos)
    assert r_pos.fired is True
    assert r_pos.severity == Severity.medium

    # Negative
    p_neg = parse_url("https://google.com/search")
    r_neg = rule_ip_host(p_neg)
    assert r_neg.fired is False


def test_userinfo_trick_rule():
    # Positive
    p_pos = parse_url("http://sbi.co.in@evil.com/login")
    r_pos = rule_userinfo_trick(p_pos)
    assert r_pos.fired is True
    assert r_pos.severity == Severity.high

    # Negative
    p_neg = parse_url("https://sbi.co.in/login")
    r_neg = rule_userinfo_trick(p_neg)
    assert r_neg.fired is False


def test_brand_in_subdomain_impersonation():
    # Positive: brand token in subdomain but registrable domain is attacker's
    p_pos = parse_url("https://sbi.netbanking-verify.xyz/login")
    d_pos = check_domain(p_pos.registrable_domain, p_pos.subdomain, p_pos.path, p_pos.host)
    r_pos = rule_brand_in_subdomain(p_pos, d_pos)
    assert r_pos.fired is True

    # Negative: official bank portal
    p_neg = parse_url("https://netbanking.hdfcbank.com/entry")
    d_neg = check_domain(p_neg.registrable_domain, p_neg.subdomain, p_neg.path, p_neg.host)
    assert d_neg.is_official is True
    r_neg = rule_brand_in_subdomain(p_neg, d_neg)
    assert r_neg.fired is False


def test_typosquat_rule():
    # Positive: typosquat domain (hdfcbonk.com is edit dist 1 from hdfcbank.com)
    p_pos = parse_url("https://hdfcbonk.com/login")
    d_pos = check_domain(p_pos.registrable_domain, p_pos.subdomain, p_pos.path, p_pos.host)
    r_pos = rule_typosquat(p_pos, d_pos)
    assert r_pos.fired is True

    # Negative: official domain
    p_neg = parse_url("https://hdfcbank.com/login")
    d_neg = check_domain(p_neg.registrable_domain, p_neg.subdomain, p_neg.path, p_neg.host)
    r_neg = rule_typosquat(p_neg, d_neg)
    assert r_neg.fired is False


def test_shortener_rule():
    # Positive
    p_pos = parse_url("https://bit.ly/xyz123")
    d_pos = check_domain(p_pos.registrable_domain, p_pos.subdomain, p_pos.path, p_pos.host)
    r_pos = rule_shortener(d_pos)
    assert r_pos.fired is True

    # Negative
    p_neg = parse_url("https://example.com/xyz123")
    d_neg = check_domain(p_neg.registrable_domain, p_neg.subdomain, p_neg.path, p_neg.host)
    r_neg = rule_shortener(d_neg)
    assert r_neg.fired is False


def test_tunnel_host_rule():
    # Positive
    p_pos = parse_url("https://my-login.trycloudflare.com/app")
    d_pos = check_domain(p_pos.registrable_domain, p_pos.subdomain, p_pos.path, p_pos.host)
    r_pos = rule_tunnel_host(p_pos, d_pos)
    assert r_pos.fired is True
    assert r_pos.severity == Severity.info  # supporting evidence only!

    # Negative
    p_neg = parse_url("https://google.com/app")
    d_neg = check_domain(p_neg.registrable_domain, p_neg.subdomain, p_neg.path, p_neg.host)
    r_neg = rule_tunnel_host(p_neg, d_neg)
    assert r_neg.fired is False


def test_embedded_redirect_rule():
    # Positive
    p_pos = parse_url("https://example.com/auth?redirect_url=http://malicious.site/steal")
    r_pos = rule_embedded_redirect(p_pos)
    assert r_pos.fired is True

    # Negative
    p_neg = parse_url("https://example.com/auth?tab=settings&page=2")
    r_neg = rule_embedded_redirect(p_neg)
    assert r_neg.fired is False


def test_legitimate_brand_portals_never_trigger_high_rules():
    """Verify official banking and login portals never trigger high-severity rules."""
    official_urls = [
        "https://netbanking.hdfcbank.com/netbanking/",
        "https://retail.onlinesbi.sbi/retail/login.htm",
        "https://infinity.icicibank.com/corp/AuthenticationController",
        "https://accounts.google.com/signin/v2/identifier",
        "https://www.instagram.com/accounts/login/",
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "https://incometax.gov.in/iec/foportal/",
        "https://myaadhaar.uidai.gov.in/",
        "https://pay.google.com/",
        "https://phonepe.com/",
    ]
    for u in official_urls:
        p = parse_url(u)
        d = check_domain(p.registrable_domain, p.subdomain, p.path, p.host)
        rules = run_url_rules(p, d)
        high_rules = [r for r in rules if r.fired and r.severity == Severity.high]
        assert len(high_rules) == 0, f"URL {u} falsely triggered high rules: {[r.rule_id for r in high_rules]}"
