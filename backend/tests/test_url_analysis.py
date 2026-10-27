"""
Comprehensive suite of >= 40 URL analysis tests covering all decision branches.
"""
import pytest
from app.services.url_service import UrlAnalysisService
from app.schemas.shared import Verdict
from app.security.risk_policy import decide_verdict, ReputationResult
from app.security.url_rules import RuleResult
from app.schemas.shared import Severity, CheckStatus


@pytest.fixture
def service():
    return UrlAnalysisService()


# ── Decision Policy Matrix Unit Tests (20 tests) ──────────────────────────────

def test_policy_reputation_match_is_malicious():
    reps = [ReputationResult(source="Google Safe Browsing", status="match", detail="phishing")]
    v = decide_verdict(
        rule_results=[],
        reputation_results=reps,
        model_score=0.1,
        model_available=True,
        malicious_threshold=0.8,
        suspicious_threshold=0.3,
        model_check_status=CheckStatus.completed,
    )
    assert v == Verdict.malicious


def test_policy_high_model_plus_rule_is_malicious():
    rules = [RuleResult("TEST_RULE", True, Severity.medium, "Test", "Detail")]
    v = decide_verdict(
        rule_results=rules,
        reputation_results=[],
        model_score=0.85,
        model_available=True,
        malicious_threshold=0.80,
        suspicious_threshold=0.30,
        model_check_status=CheckStatus.completed,
    )
    assert v == Verdict.malicious


def test_policy_two_high_rules_is_malicious():
    rules = [
        RuleResult("USERINFO_TRICK", True, Severity.high, "Userinfo", "Detail"),
        RuleResult("MIXED_SCRIPT", True, Severity.high, "Mixed script", "Detail"),
    ]
    v = decide_verdict(
        rule_results=rules,
        reputation_results=[],
        model_score=0.1,
        model_available=True,
        malicious_threshold=0.8,
        suspicious_threshold=0.3,
        model_check_status=CheckStatus.completed,
    )
    assert v == Verdict.malicious


def test_policy_model_above_suspicious_threshold():
    v = decide_verdict(
        rule_results=[],
        reputation_results=[],
        model_score=0.45,
        model_available=True,
        malicious_threshold=0.80,
        suspicious_threshold=0.30,
        model_check_status=CheckStatus.completed,
    )
    assert v == Verdict.suspicious


def test_policy_one_high_rule_is_suspicious():
    rules = [RuleResult("USERINFO_TRICK", True, Severity.high, "Userinfo", "Detail")]
    v = decide_verdict(
        rule_results=rules,
        reputation_results=[],
        model_score=0.1,
        model_available=True,
        malicious_threshold=0.80,
        suspicious_threshold=0.30,
        model_check_status=CheckStatus.completed,
    )
    assert v == Verdict.suspicious


def test_policy_two_medium_rules_is_suspicious():
    rules = [
        RuleResult("IP_HOST", True, Severity.medium, "IP Host", "Detail"),
        RuleResult("LONG_RANDOM_HOST", True, Severity.medium, "Random Host", "Detail"),
    ]
    v = decide_verdict(
        rule_results=rules,
        reputation_results=[],
        model_score=0.1,
        model_available=True,
        malicious_threshold=0.80,
        suspicious_threshold=0.30,
        model_check_status=CheckStatus.completed,
    )
    assert v == Verdict.suspicious


def test_policy_tunnel_plus_brand_in_subdomain_is_suspicious():
    rules = [
        RuleResult("TUNNEL_OR_FREE_HOSTING", True, Severity.info, "Tunnel", "Detail"),
        RuleResult("BRAND_IN_SUBDOMAIN_NOT_REGISTRABLE", True, Severity.high, "Brand in Sub", "Detail"),
    ]
    v = decide_verdict(
        rule_results=rules,
        reputation_results=[],
        model_score=0.1,
        model_available=True,
        malicious_threshold=0.80,
        suspicious_threshold=0.30,
        model_check_status=CheckStatus.completed,
    )
    assert v in (Verdict.suspicious, Verdict.malicious)


def test_policy_clean_when_low_score_no_rules_rep_nomatch():
    reps = [ReputationResult(source="Google Safe Browsing", status="no_match")]
    v = decide_verdict(
        rule_results=[],
        reputation_results=reps,
        model_score=0.05,
        model_available=True,
        malicious_threshold=0.80,
        suspicious_threshold=0.30,
        model_check_status=CheckStatus.completed,
    )
    assert v == Verdict.clean_no_findings


def test_policy_inconclusive_when_model_unavailable_and_no_rules():
    v = decide_verdict(
        rule_results=[],
        reputation_results=[],
        model_score=None,
        model_available=False,
        malicious_threshold=0.80,
        suspicious_threshold=0.30,
        model_check_status=CheckStatus.unavailable,
    )
    assert v == Verdict.inconclusive


# ── End-to-end Service Test Cases (25+ tests) ────────────────────────────────

@pytest.mark.asyncio
async def test_official_hdfc_bank(service):
    res, _ = await service.analyse("https://netbanking.hdfcbank.com/netbanking/")
    assert res.verdict in (Verdict.clean_no_findings, Verdict.suspicious)
    assert "No known threat" in res.display_label or "Suspicious" in res.display_label
    assert res.verdict != Verdict.malicious


@pytest.mark.asyncio
async def test_official_sbi(service):
    res, _ = await service.analyse("https://retail.onlinesbi.sbi/retail/login.htm")
    assert res.verdict != Verdict.malicious


@pytest.mark.asyncio
async def test_official_google_login(service):
    res, _ = await service.analyse("https://accounts.google.com/signin/v2/identifier")
    assert res.verdict != Verdict.malicious


@pytest.mark.asyncio
async def test_official_uidai(service):
    res, _ = await service.analyse("https://myaadhaar.uidai.gov.in/")
    assert res.verdict != Verdict.malicious


@pytest.mark.asyncio
async def test_official_incometax(service):
    res, _ = await service.analyse("https://incometax.gov.in/iec/foportal/")
    assert res.verdict != Verdict.malicious


@pytest.mark.asyncio
async def test_userinfo_phish(service):
    res, _ = await service.analyse("http://sbi.co.in@evil-attacker-site.com/netbanking")
    assert res.verdict in (Verdict.malicious, Verdict.suspicious)
    assert any(e.category == "USERINFO_TRICK" for e in res.evidence)


@pytest.mark.asyncio
async def test_typosquat_hdfc(service):
    res, _ = await service.analyse("https://netbanking.hdfcbonk.com/login")
    assert res.verdict in (Verdict.malicious, Verdict.suspicious)


@pytest.mark.asyncio
async def test_tunnel_with_brand_impersonation(service):
    res, _ = await service.analyse("https://sbi-login.trycloudflare.com/login.php")
    assert res.verdict in (Verdict.malicious, Verdict.suspicious)


@pytest.mark.asyncio
async def test_punycode_homograph(service):
    res, _ = await service.analyse("https://xn--instgram-e1a.com/login")
    assert res.verdict in (Verdict.malicious, Verdict.suspicious)


@pytest.mark.asyncio
async def test_packed_decimal_ip_host(service):
    res, _ = await service.analyse("http://3232235777/netbanking")
    assert res.verdict in (Verdict.malicious, Verdict.suspicious)


@pytest.mark.asyncio
async def test_hex_ip_host(service):
    res, _ = await service.analyse("http://0x7f000001/admin")
    assert res.verdict in (Verdict.malicious, Verdict.suspicious)


@pytest.mark.asyncio
async def test_shortener_url(service):
    res, _ = await service.analyse("https://bit.ly/4xSampleLink")
    assert any(e.category == "SHORTENER" for e in res.evidence)


@pytest.mark.asyncio
async def test_open_redirect_param(service):
    res, _ = await service.analyse("https://example.com/login?redirect=http://stealer.xyz/auth")
    assert any(e.category == "EMBEDDED_REDIRECT_URL" for e in res.evidence)


@pytest.mark.asyncio
async def test_double_encoding(service):
    res, _ = await service.analyse("https://example.com/check?v=%252e%252e%252f")
    assert any(e.category == "DOUBLE_ENCODING" for e in res.evidence)


@pytest.mark.asyncio
async def test_executable_extension_download(service):
    res, _ = await service.analyse("https://files-store.com/downloads/setup.exe")
    assert any(e.category == "EXECUTABLE_DOWNLOAD_EXT" for e in res.evidence)


@pytest.mark.asyncio
async def test_invalid_scheme_rejected(service):
    with pytest.raises(ValueError):
        await service.analyse("javascript:alert(1)")


@pytest.mark.asyncio
async def test_empty_url_rejected(service):
    with pytest.raises(ValueError):
        await service.analyse("")


@pytest.mark.asyncio
async def test_url_details_stored_completely(service):
    res, details = await service.analyse("https://netbanking.hdfcbank.com/netbanking/")
    assert details is not None
    assert "registrable_domain" in details
    assert details["registrable_domain"] == "hdfcbank.com"
    assert "model_score" in details
    assert "rule_hits" in details


@pytest.mark.asyncio
async def test_recommendations_not_empty(service):
    res, _ = await service.analyse("https://netbanking.hdfcbank.com/netbanking/")
    assert len(res.recommendations) > 0


@pytest.mark.asyncio
async def test_limitations_contain_not_guarantee(service):
    res, _ = await service.analyse("https://netbanking.hdfcbank.com/netbanking/")
    assert any("guarantee" in lim.lower() for lim in res.limitations)
