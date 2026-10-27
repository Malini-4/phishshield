"""
Unit tests for Android APK static analysis module.
Programmatically builds synthetic APK ZIP fixtures to safely test parsers and rules without executing malware.
"""
import io
import zipfile
import pytest
from app.services.apk_service import (
    ApkAnalysisService,
    _is_valid_apk,
    _check_zip_bomb,
    _classify_permissions,
    _apply_apk_rules,
)
from app.schemas.shared import Verdict


@pytest.fixture
def service():
    return ApkAnalysisService()


def create_synthetic_apk(
    manifest_bytes: bytes = b"<manifest package='com.example.app'></manifest>",
    dex_bytes: bytes = b"dex\n035\x00dummy_dex_data",
    extra_files: dict = None,
) -> bytes:
    """Build a programmatically generated minimal APK (ZIP) fixture."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", manifest_bytes)
        z.writestr("classes.dex", dex_bytes)
        if extra_files:
            for fname, content in extra_files.items():
                z.writestr(fname, content)
    return buf.getvalue()


def test_is_valid_apk_checker():
    # Valid synthetic APK
    apk = create_synthetic_apk()
    assert _is_valid_apk(apk) is True

    # Plain text / non-zip
    assert _is_valid_apk(b"hello world") is False

    # ZIP without AndroidManifest.xml
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("test.txt", b"hello")
    assert _is_valid_apk(buf.getvalue()) is False


def test_zip_bomb_detection():
    # Synthetic high ratio entry
    apk = create_synthetic_apk(dex_bytes=b"\x00" * 200000)
    # Check with very strict limit to verify detection logic
    bomb_err = _check_zip_bomb(apk, max_ratio=5)
    assert bomb_err is not None
    assert "ratio" in bomb_err.lower()


def test_permission_classification():
    perms = [
        "android.permission.READ_SMS",
        "android.permission.INTERNET",
        "android.permission.CAMERA",
    ]
    classified = _classify_permissions(perms)
    assert len(classified) == 3
    read_sms = next(p for p in classified if p["permission"] == "android.permission.READ_SMS")
    assert read_sms["severity"] == "high"


def test_banking_trojan_pattern_rule():
    parsed = {
        "package_name": "com.evil.bankdropper",
        "permissions": [
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.SYSTEM_ALERT_WINDOW",
        ],
        "strings": [],
    }
    evidence = _apply_apk_rules(parsed)
    assert any(e.category == "BANKING_TROJAN_PATTERN" for e in evidence)


def test_package_impersonation_rule():
    parsed = {
        "package_name": "com.sbi.fakebanking.app",
        "permissions": ["android.permission.INTERNET"],
        "strings": [],
    }
    evidence = _apply_apk_rules(parsed)
    assert any(e.category == "PACKAGE_IMPERSONATION" for e in evidence)


@pytest.mark.asyncio
async def test_corrupted_file_returns_inconclusive(service):
    corrupt_bytes = b"PK\x03\x04corrupted_zip_payload_with_broken_headers"
    res, details = await service.analyse(corrupt_bytes, "test.apk")
    assert res.verdict == Verdict.inconclusive
    assert "not a valid" in res.summary or "Could not parse" in res.summary


@pytest.mark.asyncio
async def test_synthetic_apk_analysis_flow(service):
    apk = create_synthetic_apk()
    res, details = await service.analyse(apk, "sample.apk")
    assert res.verdict in (Verdict.clean_no_findings, Verdict.suspicious, Verdict.inconclusive)
    assert details is not None
    assert "sha256" in details
    assert len(details["sha256"]) == 64
