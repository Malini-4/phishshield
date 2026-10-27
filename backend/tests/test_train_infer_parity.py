"""
Test parity between ML training feature extraction and live inference feature extraction.
"""
from __future__ import annotations

import pytest
from app.security.url_parser import parse_url
from app.security.url_features import extract_features, FEATURE_NAMES
from app.security.domain_checks import check_domain, enrich_features
from app.services.model_loader import get_model


def test_feature_names_order_and_contract():
    model, err = get_model()
    assert model is not None, f"Model must be loaded: {err}"
    assert model.feature_names == FEATURE_NAMES
    assert len(FEATURE_NAMES) == 43


def test_feature_parity_sample_urls():
    test_urls = [
        "https://netbanking.hdfcbank.com/netbanking/",
        "http://3232235777/login.php",
        "https://sbi-secure.trycloudflare.com/verify?id=123",
        "https://www.paypal.com@evil-phish.xyz/login",
        "https://xn--instgram-e1a.com/auth",
        "https://bit.ly/3xSample",
    ]

    model, _ = get_model()
    assert model is not None

    for u in test_urls:
        parsed = parse_url(u)
        assert not isinstance(parsed, Exception)
        dom = check_domain(parsed.registrable_domain, parsed.subdomain, parsed.path, parsed.host)
        feats = extract_features(parsed)
        feats = enrich_features(feats, dom)

        # Vector matches FEATURE_NAMES order
        vec = [feats[f] for f in FEATURE_NAMES]
        assert len(vec) == len(FEATURE_NAMES)

        # Model scores without error
        prob = model.score(feats)
        assert 0.0 <= prob <= 1.0
        assert model.band(prob) in ("low", "medium", "high")
