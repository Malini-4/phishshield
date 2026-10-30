"""
Tests for APK fixes:
1. Real F-Droid-like app is clean (clean_no_findings) despite REQUEST_INSTALL_PACKAGES.
2. Powerful permissions: ONE low-severity note (medium only if unknown and >= 4 powerful permissions).
3. Combinations: Banking trojan (high), SMS + overlay/accessibility (medium), SMS + api.telegram.org (high).
4. Lowered severities for SUSPICIOUS_STRINGS.
5. Reading debuggable flag via get_attribute_value.
6. Certificate SHA-256 fingerprint extraction.
7. assess_trust function & trusted_apps.csv.
8. Low severity for known brand sub-packages (e.g. com.google.*).
"""
import hashlib
from unittest.mock import MagicMock

from app.schemas.shared import Severity, Verdict
from app.services.apk_service import (
    POWERFUL_PERMISSIONS,
    SUSPICIOUS_STRINGS,
    _apply_apk_rules,
    _decide_apk_verdict,
    assess_trust,
    load_trusted_apps,
)


def test_trusted_apps_catalog_loaded():
    trusted = load_trusted_apps()
    assert "org.fdroid.fdroid" in trusted
    assert "com.phonepe.app" in trusted
    assert "com.whatsapp" in trusted
    assert "in.org.npci.upiapp" in trusted


def test_assess_trust():
    # Known app with empty cert on file -> known_unverified
    status = assess_trust("org.fdroid.fdroid", ["some_hash"])
    assert status == "known_unverified"

    # Unknown package
    status_unk = assess_trust("com.evil.malware", ["some_hash"])
    assert status_unk == "unknown"


def test_assess_trust_cert_mismatch_and_verified():
    # Mock trusted apps catalog with an expected fingerprint
    mock_catalog = {
        "com.example.bank": {
            "app_name": "Example Bank",
            "publisher": "Example Bank Ltd",
            "cert_sha256": "EXPECTED_HASH",
            "notes": "",
        }
    }
    from unittest.mock import patch
    with patch("app.services.apk_service.load_trusted_apps", return_value=mock_catalog):
        # Matching certificate -> verified
        assert assess_trust("com.example.bank", ["EXPECTED_HASH"]) == "verified"
        # Mismatched certificate -> cert_mismatch
        assert assess_trust("com.example.bank", ["DIFFERENT_HASH"]) == "cert_mismatch"


def test_fdroid_like_app_is_clean():
    # F-Droid requests REQUEST_INSTALL_PACKAGES as an app installer
    parsed = {
        "package_name": "org.fdroid.fdroid",
        "app_label": "F-Droid",
        "permissions": ["android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.INTERNET"],
        "certificates": ["cert123"],
        "debuggable": False,
        "strings": [],
    }
    evidence = _apply_apk_rules(parsed)
    # Powerful permissions should only be low severity, not medium
    powerful_ev = [e for e in evidence if e.category == "POWERFUL_PERMISSIONS"]
    assert len(powerful_ev) == 1
    assert powerful_ev[0].severity == Severity.low

    verdict = _decide_apk_verdict(evidence)
    assert verdict == Verdict.clean_no_findings


def test_powerful_permissions_medium_only_for_unknown_and_4_or_more():
    # Unknown app with 3 powerful permissions -> low severity
    parsed_3 = {
        "package_name": "com.unknown.tools",
        "permissions": [
            "android.permission.REQUEST_INSTALL_PACKAGES",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
        ],
        "certificates": [],
        "debuggable": False,
        "strings": [],
    }
    ev_3 = _apply_apk_rules(parsed_3)
    p_ev_3 = [e for e in ev_3 if e.category == "POWERFUL_PERMISSIONS"]
    assert len(p_ev_3) == 1
    assert p_ev_3[0].severity == Severity.low

    # Unknown app with 4 powerful permissions -> medium severity
    parsed_4 = {
        "package_name": "com.unknown.tools",
        "permissions": [
            "android.permission.REQUEST_INSTALL_PACKAGES",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.BIND_DEVICE_ADMIN",
        ],
        "certificates": [],
        "debuggable": False,
        "strings": [],
    }
    ev_4 = _apply_apk_rules(parsed_4)
    p_ev_4 = [e for e in ev_4 if e.category == "POWERFUL_PERMISSIONS"]
    assert len(p_ev_4) == 1
    assert p_ev_4[0].severity == Severity.medium


def test_combo_sms_overlay_accessibility_medium():
    parsed = {
        "package_name": "com.utility.scanner",
        "permissions": [
            "android.permission.READ_SMS",
            "android.permission.SYSTEM_ALERT_WINDOW",
        ],
        "certificates": [],
        "debuggable": False,
        "strings": [],
    }
    evidence = _apply_apk_rules(parsed)
    combo_ev = [e for e in evidence if e.category == "SMS_OVERLAY_COMBO"]
    assert len(combo_ev) == 1
    assert combo_ev[0].severity == Severity.medium


def test_combo_sms_telegram_exfiltration_high():
    parsed = {
        "package_name": "com.utility.smsreader",
        "permissions": ["android.permission.READ_SMS"],
        "certificates": [],
        "debuggable": False,
        "strings": [
            {"type": "suspicious", "value": "api.telegram.org", "desc": "Telegram bot API", "severity": "medium"}
        ],
    }
    evidence = _apply_apk_rules(parsed)
    tele_ev = [e for e in evidence if e.category == "SMS_TELEGRAM_EXFILTRATION"]
    assert len(tele_ev) == 1
    assert tele_ev[0].severity == Severity.high


def test_suspicious_strings_severities():
    # Verify that api.telegram.org and DexClassLoader are medium, Runtime.exec is low
    susp_dict = {pattern: sev for pattern, sev, desc in SUSPICIOUS_STRINGS}
    assert susp_dict["api.telegram.org"] == "medium"
    assert susp_dict["DexClassLoader"] == "medium"
    assert susp_dict["Runtime.exec"] == "low"
    assert susp_dict["SmsManager.sendTextMessage"] == "medium"


def test_cert_mismatch_creates_high_evidence():
    parsed = {
        "package_name": "com.example.bank",
        "certificates": ["TAMPERED_CERT_HASH"],
        "permissions": [],
        "debuggable": False,
        "strings": [],
    }
    mock_catalog = {
        "com.example.bank": {
            "app_name": "Example Bank",
            "publisher": "Example Bank Ltd",
            "cert_sha256": "ORIGINAL_CERT_HASH",
            "notes": "",
        }
    }
    from unittest.mock import patch
    with patch("app.services.apk_service.load_trusted_apps", return_value=mock_catalog):
        evidence = _apply_apk_rules(parsed)
        mismatch_ev = [e for e in evidence if e.category == "CERT_MISMATCH"]
        assert len(mismatch_ev) == 1
        assert mismatch_ev[0].severity == Severity.high


def test_brand_prefix_sub_package_low_severity():
    # Unlisted app starting with com.google. containing brand word -> LOW severity
    parsed = {
        "package_name": "com.google.android.apps.unlistedbrandfeature",
        "permissions": [],
        "certificates": [],
        "debuggable": False,
        "strings": [],
    }
    evidence = _apply_apk_rules(parsed)
    pkg_ev = [e for e in evidence if e.category == "PACKAGE_IMPERSONATION"]
    assert len(pkg_ev) == 1
    assert pkg_ev[0].severity == Severity.low
