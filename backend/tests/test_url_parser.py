"""
Unit tests for URL Parser.
"""
import pytest
from app.security.url_parser import parse_url, ValidationError


def test_empty_and_long_url():
    assert isinstance(parse_url(""), ValidationError)
    assert isinstance(parse_url("   "), ValidationError)
    assert isinstance(parse_url("http://" + "a" * 2050 + ".com"), ValidationError)


def test_blocked_schemes():
    assert isinstance(parse_url("javascript:alert(1)"), ValidationError)
    assert isinstance(parse_url("data:text/html,<script>"), ValidationError)
    assert isinstance(parse_url("file:///etc/passwd"), ValidationError)
    assert isinstance(parse_url("ftp://server.com/file"), ValidationError)


def test_missing_scheme_assumes_http():
    p = parse_url("example.com/path")
    assert not isinstance(p, ValidationError)
    assert p.scheme == "http"
    assert p.scheme_was_missing is True
    assert p.host == "example.com"


def test_userinfo_at_trick():
    p = parse_url("http://sbi.co.in@evil-attacker.com/login")
    assert not isinstance(p, ValidationError)
    assert p.userinfo == "sbi.co.in"
    assert p.host == "evil-attacker.com"
    assert p.registrable_domain == "evil-attacker.com"


def test_ip_detection_forms():
    # standard dotted
    p1 = parse_url("http://192.168.1.1/admin")
    assert p1.is_ip is True
    assert p1.ip_form == "decimal"

    # packed decimal
    p2 = parse_url("http://3232235777/test")
    assert p2.is_ip is True
    assert p2.ip_form == "decimal_packed"
    assert p2.ip_address == "192.168.1.1"

    # hex
    p3 = parse_url("http://0x7f000001/")
    assert p3.is_ip is True
    assert p3.ip_form == "hex"

    # octal
    p4 = parse_url("http://017700000001/")
    assert p4.is_ip is True
    assert p4.ip_form == "octal"


def test_punycode_and_idn():
    p = parse_url("https://xn--instgram-e1a.com/login")
    assert not isinstance(p, ValidationError)
    assert p.is_idna is True


def test_double_encoding_detection():
    p = parse_url("https://example.com/path?param=%252e%252e%252f")
    assert not isinstance(p, ValidationError)
    assert p.double_encoding_detected is True


def test_registrable_domain_extraction():
    p = parse_url("https://netbanking.hdfcbank.com/netbanking/entry")
    assert p.registrable_domain == "hdfcbank.com"
    assert p.subdomain == "netbanking"
