"""
APK Static Analysis Service.
Never executes, installs or emulates the APK.
"""
from __future__ import annotations

import csv
import hashlib
import logging
import time
import uuid
import zipfile
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Optional

from app.config import get_settings
from app.schemas.shared import (
    AnalysisResult, CheckPerformed, CheckStatus, EvidenceItem, EvidenceSource,
    ModuleType, Severity, Verdict, make_display_label, standard_recommendations,
)

logger = logging.getLogger(__name__)
_DATA_DIR = Path(__file__).parent.parent.parent.parent / "data" / "reference"

SENSITIVE_PERMISSIONS = {
    "android.permission.READ_SMS": ("high", "Can read all your SMS messages"),
    "android.permission.RECEIVE_SMS": ("high", "Can intercept incoming SMS messages"),
    "android.permission.SEND_SMS": ("high", "Can send SMS without your knowledge"),
    "android.permission.READ_CONTACTS": ("medium", "Can read all your contacts"),
    "android.permission.READ_CALL_LOG": ("medium", "Can read your call history"),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": ("high", "Can control your screen and apps"),
    "android.permission.SYSTEM_ALERT_WINDOW": ("high", "Can overlay on top of other apps"),
    "android.permission.REQUEST_INSTALL_PACKAGES": ("high", "Can silently install other apps"),
    "android.permission.BIND_DEVICE_ADMIN": ("high", "Can control device as admin"),
    "android.permission.READ_PHONE_STATE": ("medium", "Can read phone number and IMEI"),
    "android.permission.RECORD_AUDIO": ("medium", "Can record microphone"),
    "android.permission.CAMERA": ("medium", "Can access camera"),
    "android.permission.ACCESS_FINE_LOCATION": ("medium", "Can track precise GPS location"),
    "android.permission.MANAGE_EXTERNAL_STORAGE": ("medium", "Can access all files"),
    "android.permission.QUERY_ALL_PACKAGES": ("low", "Can see all installed apps"),
    "android.permission.RECEIVE_BOOT_COMPLETED": ("low", "Can start automatically on boot"),
    "android.permission.PACKAGE_USAGE_STATS": ("medium", "Can monitor which apps you use"),
    "android.permission.WRITE_SETTINGS": ("medium", "Can change system settings"),
}

POWERFUL_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.BIND_DEVICE_ADMIN",
}

SUSPICIOUS_STRINGS = [
    ("api.telegram.org", "medium", "Telegram bot API endpoint"),
    ("DexClassLoader", "medium", "Dynamic code loading (malware indicator)"),
    ("Runtime.exec", "low", "Shell command execution"),
    ("AccessibilityService", "low", "Accessibility service reference"),
    ("BIND_ACCESSIBILITY_SERVICE", "low", "Accessibility binding reference"),
    ("WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY", "low", "Screen overlay"),
    ("SmsManager.sendTextMessage", "medium", "SMS sending code"),
    ("TelephonyManager.getDeviceId", "low", "Device ID collection"),
]

OFFICIAL_PACKAGES = {
    "com.google.android.apps.tez": "Google Pay",
    "com.phonepe.app": "PhonePe",
    "net.one97.paytm": "Paytm",
    "in.org.npci.upiapp": "BHIM",
    "com.sbi.lotusintouch": "SBI YONO",
    "com.hdfcbank.payzapp": "HDFC PayZapp",
    "com.whatsapp": "WhatsApp",
    "com.facebook.katana": "Facebook",
    "com.instagram.android": "Instagram",
    "com.amazon.mShop.android.shopping": "Amazon",
    "com.flipkart.android": "Flipkart",
}


@lru_cache(maxsize=1)
def load_trusted_apps() -> dict[str, dict]:
    path = _DATA_DIR / "trusted_apps.csv"
    trusted = {}
    if not path.exists():
        return trusted
    try:
        with open(path, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                pkg = (row.get("package") or "").strip()
                if pkg:
                    trusted[pkg] = dict(row)
    except Exception as e:
        logger.error(f"Failed to load trusted apps: {e}")
    return trusted


def assess_trust(package: Optional[str], cert_fingerprints: Optional[list[str]] = None) -> str:
    """
    Returns:
    - 'verified' (cert matches)
    - 'cert_mismatch' (known package, cert on file, different signer -> HIGH finding)
    - 'known_unverified' (listed but no cert on file -> info only)
    - 'unknown'
    """
    if not package or not package.strip():
        return "unknown"
    pkg = package.strip()
    trusted = load_trusted_apps()
    if pkg not in trusted:
        return "unknown"

    entry = trusted[pkg]
    stored_cert = (entry.get("cert_sha256") or "").strip().lower()
    fingerprints = [c.strip().lower() for c in (cert_fingerprints or []) if c and c.strip()]

    if stored_cert:
        if any(f == stored_cert for f in fingerprints):
            return "verified"
        if fingerprints:
            return "cert_mismatch"
        return "known_unverified"

    return "known_unverified"


def _compute_hashes(data: bytes) -> tuple[str, str]:
    sha256 = hashlib.sha256(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()
    return sha256, md5


def _is_valid_apk(data: bytes) -> bool:
    """Check magic bytes and presence of AndroidManifest.xml."""
    if not data[:4] == b'PK\x03\x04':
        return False
    try:
        import io
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            names = z.namelist()
            return 'AndroidManifest.xml' in names
    except Exception:
        return False


def _check_zip_bomb(data: bytes, max_entries: int = 1000, max_uncompressed_mb: int = 500,
                    max_ratio: int = 100) -> Optional[str]:
    """Check for zip bomb characteristics. Never extracts to disk."""
    try:
        import io
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            infos = z.infolist()
            if len(infos) > max_entries:
                return f"Too many entries in ZIP ({len(infos)} > {max_entries})"
            total_uncompressed = sum(i.file_size for i in infos)
            max_bytes = max_uncompressed_mb * 1024 * 1024
            if total_uncompressed > max_bytes:
                return f"Uncompressed size too large ({total_uncompressed // (1024*1024)} MB > {max_uncompressed_mb} MB)"
            compressed = sum(i.compress_size for i in infos)
            if compressed > 0 and total_uncompressed / compressed > max_ratio:
                return f"Compression ratio too high ({total_uncompressed / compressed:.0f}x > {max_ratio}x)"
    except zipfile.BadZipFile as e:
        return f"Invalid ZIP: {e}"
    return None


def _parse_with_androguard(data: bytes) -> Optional[dict]:
    """Try parsing with androguard."""
    try:
        from androguard.core.apk import APK  # type: ignore
        import io
        apk = APK(data, raw=True)
        permissions = apk.get_permissions() or []
        activities = apk.get_activities() or []
        services = apk.get_services() or []
        receivers = apk.get_receivers() or []

        # DEX string scan
        strings_found = []
        try:
            from androguard.core.dex import DEX  # type: ignore
            dex_data = apk.get_dex()
            if dex_data:
                dvm = DEX(dex_data)
                for s in dvm.get_strings():
                    s_str = str(s)
                    if s_str.startswith("http://") or s_str.startswith("https://"):
                        strings_found.append({"type": "url", "value": s_str[:200]})
                    for pattern, sev, desc in SUSPICIOUS_STRINGS:
                        if pattern in s_str:
                            strings_found.append({
                                "type": "suspicious", "value": pattern,
                                "severity": sev, "desc": desc,
                            })
        except Exception as e:
            logger.debug(f"DEX string scan failed: {e}")

        # Debuggable attribute check
        debuggable = False
        try:
            val = apk.get_attribute_value("application", "debuggable")
            if isinstance(val, str):
                debuggable = val.strip().lower() in ("true", "1")
            elif isinstance(val, bool):
                debuggable = val
            elif val is not None:
                debuggable = bool(val)
        except Exception as e:
            logger.debug(f"Failed to read debuggable: {e}")

        # Signing certificate fingerprints
        cert_hashes: list[str] = []
        try:
            certs = apk.get_certificates() or []
            for cert in certs:
                try:
                    if hasattr(cert, "dump"):
                        raw_bytes = cert.dump()
                        if isinstance(raw_bytes, bytes):
                            cert_hashes.append(hashlib.sha256(raw_bytes).hexdigest().lower())
                    elif hasattr(cert, "sha256"):
                        cert_hashes.append(str(cert.sha256).lower())
                except Exception as ce:
                    logger.debug(f"Failed to dump certificate: {ce}")
        except Exception as e:
            logger.debug(f"apk.get_certificates failed: {e}")

        return {
            "package_name": apk.get_package(),
            "app_label": apk.get_app_name(),
            "version_name": apk.get_androidversion_name(),
            "version_code": apk.get_androidversion_code(),
            "min_sdk": str(apk.get_min_sdk_version() or ""),
            "target_sdk": str(apk.get_target_sdk_version() or ""),
            "permissions": permissions,
            "activities": activities,
            "services": services,
            "receivers": receivers,
            "debuggable": debuggable,
            "allow_backup": False,
            "certificates": cert_hashes,
            "strings": strings_found,
            "parser": "androguard",
        }
    except ImportError:
        return None
    except Exception as e:
        logger.warning(f"androguard parse failed: {e}")
        return None


def _parse_with_pyaxmlparser(data: bytes) -> Optional[dict]:
    """Fallback: pyaxmlparser for manifest only."""
    try:
        from pyaxmlparser import APK  # type: ignore
        import io
        apk = APK(io.BytesIO(data))
        return {
            "package_name": apk.package,
            "app_label": getattr(apk, 'application_label', None),
            "version_name": apk.version_name,
            "version_code": apk.version_code,
            "min_sdk": getattr(apk, 'min_sdk_version', None),
            "target_sdk": getattr(apk, 'target_sdk_version', None),
            "permissions": list(apk.permissions or []),
            "activities": [],
            "services": [],
            "receivers": [],
            "debuggable": False,
            "allow_backup": False,
            "certificates": [],
            "strings": [],
            "parser": "pyaxmlparser",
        }
    except ImportError:
        return None
    except Exception as e:
        logger.warning(f"pyaxmlparser parse failed: {e}")
        return None


def _parse_minimal_zip(data: bytes) -> Optional[dict]:
    """Last resort: parse just the manifest XML from the ZIP."""
    try:
        import io
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            if 'AndroidManifest.xml' not in z.namelist():
                return None
            # Can't parse binary AXML without androguard/pyaxmlparser
            return {
                "package_name": None,
                "app_label": None,
                "version_name": None,
                "version_code": None,
                "min_sdk": None,
                "target_sdk": None,
                "permissions": [],
                "activities": [],
                "services": [],
                "receivers": [],
                "debuggable": False,
                "allow_backup": False,
                "certificates": [],
                "strings": [],
                "parser": "minimal_zip",
            }
    except Exception:
        return None


def _classify_permissions(permissions: list[str]) -> list[dict]:
    classified = []
    for perm in permissions:
        if perm in SENSITIVE_PERMISSIONS:
            sev, desc = SENSITIVE_PERMISSIONS[perm]
            classified.append({"permission": perm, "severity": sev, "description": desc})
        else:
            short = perm.split(".")[-1] if "." in perm else perm
            classified.append({"permission": perm, "severity": "info", "description": short})
    return classified


def _apply_apk_rules(parsed: dict) -> list[EvidenceItem]:
    evidence = []
    permissions = set(parsed.get("permissions", []))
    pkg = parsed.get("package_name", "") or ""
    cert_fingerprints = parsed.get("certificates", [])

    # Trust assessment from reference catalog
    trust_status = assess_trust(pkg, cert_fingerprints)
    if trust_status == "cert_mismatch":
        evidence.append(EvidenceItem(
            category="CERT_MISMATCH",
            severity=Severity.high,
            title="Signing certificate mismatch for known app",
            detail=f"Package '{pkg}' is in the trusted catalog, but its signing certificate does not match the registered certificate fingerprint. This strongly indicates a repackaged or counterfeit APK.",
            source=EvidenceSource.rule,
        ))
    elif trust_status == "known_unverified":
        evidence.append(EvidenceItem(
            category="TRUSTED_APP_INFO",
            severity=Severity.info,
            title="Known application catalog entry",
            detail=f"Package '{pkg}' matches a known application in our reference catalog (no certificate fingerprint on file).",
            source=EvidenceSource.rule,
        ))
    elif trust_status == "verified":
        evidence.append(EvidenceItem(
            category="TRUSTED_APP_VERIFIED",
            severity=Severity.info,
            title="Verified application signature",
            detail=f"Package '{pkg}' certificate fingerprint matches the trusted catalog.",
            source=EvidenceSource.rule,
        ))

    # Combinations & Trojan patterns
    sms_read = "android.permission.READ_SMS" in permissions
    sms_send = "android.permission.SEND_SMS" in permissions
    sms_receive = "android.permission.RECEIVE_SMS" in permissions
    boot_recv = "android.permission.RECEIVE_BOOT_COMPLETED" in permissions
    overlay = "android.permission.SYSTEM_ALERT_WINDOW" in permissions
    accessibility = "android.permission.BIND_ACCESSIBILITY_SERVICE" in permissions

    has_banking_trojan = (sms_read or sms_receive) and sms_send and boot_recv and (overlay or accessibility)
    if has_banking_trojan:
        evidence.append(EvidenceItem(
            category="BANKING_TROJAN_PATTERN",
            severity=Severity.high,
            title="Possible banking trojan permission pattern",
            detail="This app requests SMS interception, SMS sending, boot persistence, "
                   "and overlay/accessibility – a classic banking malware combination.",
            source=EvidenceSource.rule,
        ))

    # Combination: READ/RECEIVE_SMS + overlay or accessibility (medium)
    if (sms_read or sms_receive) and (overlay or accessibility) and not has_banking_trojan:
        evidence.append(EvidenceItem(
            category="SMS_OVERLAY_COMBO",
            severity=Severity.medium,
            title="SMS access combined with screen overlay or accessibility",
            detail="App requests both SMS interception and overlay/accessibility permissions, which can be abused to steal 2FA codes and overlay phishing interfaces.",
            source=EvidenceSource.rule,
        ))

    # Combination: READ/RECEIVE_SMS + api.telegram.org in code (high)
    has_telegram = any(
        s.get("value") == "api.telegram.org" or "api.telegram.org" in str(s.get("value", ""))
        for s in parsed.get("strings", [])
    )
    if (sms_read or sms_receive) and has_telegram:
        evidence.append(EvidenceItem(
            category="SMS_TELEGRAM_EXFILTRATION",
            severity=Severity.high,
            title="SMS access combined with Telegram API endpoint",
            detail="App requests SMS access and includes api.telegram.org in code, a classic pattern for SMS stealer command-and-control exfiltration.",
            source=EvidenceSource.rule,
        ))

    # Rule 2: Package name impersonation
    brand_tokens = {"sbi", "hdfc", "icici", "paytm", "phonepe", "gpay", "bhim",
                    "google", "whatsapp", "facebook", "instagram", "amazon", "flipkart"}
    trusted = load_trusted_apps()
    is_known = pkg in trusted or pkg in OFFICIAL_PACKAGES
    for brand in brand_tokens:
        if brand in pkg.lower() and not is_known:
            official_prefixes = (
                "com.google.", "com.whatsapp", "com.facebook.",
                "com.instagram.", "com.amazon.", "in.amazon.", "com.flipkart."
            )
            is_sub_brand = any(pkg.startswith(p) for p in official_prefixes)
            sev = Severity.low if is_sub_brand else Severity.medium
            evidence.append(EvidenceItem(
                category="PACKAGE_IMPERSONATION",
                severity=sev,
                title=f"Package name resembles '{brand}' (sub-brand / legitimate prefix)" if is_sub_brand else f"Package name resembles '{brand}' but is not the official app",
                detail=f"Package '{pkg}' contains '{brand}' but doesn't match any known official package ID.",
                source=EvidenceSource.rule,
            ))
            break

    # Rule 3: Debuggable
    if parsed.get("debuggable"):
        evidence.append(EvidenceItem(
            category="DEBUG_FLAG",
            severity=Severity.medium,
            title="App is marked as debuggable",
            detail="Release apps should not be debuggable. This may indicate a modified/unofficial version.",
            source=EvidenceSource.rule,
        ))

    # Rule 4: Suspicious strings from DEX
    seen_patterns: set[str] = set()
    for s in parsed.get("strings", []):
        if s.get("type") == "suspicious" and s["value"] not in seen_patterns:
            sev_str = s.get("severity", "low")
            sev_map = {"high": Severity.high, "medium": Severity.medium, "low": Severity.low}
            evidence.append(EvidenceItem(
                category="SUSPICIOUS_STRING",
                severity=sev_map.get(sev_str, Severity.low),
                title=f"Suspicious code pattern: {s['value']}",
                detail=s.get("desc", ""),
                source=EvidenceSource.parser,
            ))
            seen_patterns.add(s["value"])

    # Rule 5: Cleartext IP endpoints
    http_urls = [s["value"] for s in parsed.get("strings", []) if s.get("type") == "url" and "http://" in s.get("value", "")]
    ip_urls = [u for u in http_urls if _looks_like_ip_url(u)]
    if ip_urls:
        evidence.append(EvidenceItem(
            category="CLEARTEXT_IP_ENDPOINT",
            severity=Severity.medium,
            title=f"Cleartext HTTP endpoints with IP addresses ({len(ip_urls)})",
            detail=f"Found: {ip_urls[0][:80]} – may indicate C2 communication.",
            source=EvidenceSource.parser,
        ))

    # Powerful permissions: Add ONE note instead of a medium finding per permission.
    # Medium only if the app is unknown AND has 4 or more powerful permissions.
    powerful_found = [p for p in permissions if p in POWERFUL_PERMISSIONS]
    if powerful_found:
        if trust_status == "unknown" and len(powerful_found) >= 4:
            evidence.append(EvidenceItem(
                category="POWERFUL_PERMISSIONS",
                severity=Severity.medium,
                title=f"Multiple powerful permissions requested ({len(powerful_found)})",
                detail=f"Unknown app requests {len(powerful_found)} powerful permissions: {', '.join(p.split('.')[-1] for p in powerful_found)}.",
                source=EvidenceSource.parser,
            ))
        else:
            evidence.append(EvidenceItem(
                category="POWERFUL_PERMISSIONS",
                severity=Severity.low,
                title=f"Powerful permissions requested ({len(powerful_found)})",
                detail=f"App requests powerful permission(s): {', '.join(p.split('.')[-1] for p in powerful_found)}.",
                source=EvidenceSource.parser,
            ))

    return evidence


def _looks_like_ip_url(url: str) -> bool:
    import re
    return bool(re.search(r"http://\d+\.\d+\.\d+\.\d+", url))


def _decide_apk_verdict(evidence: list[EvidenceItem]) -> Verdict:
    high_count = sum(1 for e in evidence if e.severity == Severity.high)
    medium_count = sum(1 for e in evidence if e.severity == Severity.medium)
    if high_count >= 1:
        return Verdict.malicious
    if medium_count >= 2:
        return Verdict.suspicious
    if medium_count >= 1:
        return Verdict.suspicious
    return Verdict.clean_no_findings


class ApkAnalysisService:
    def __init__(self):
        self.settings = get_settings()

    async def analyse(self, data: bytes, filename: str = "upload.apk") -> tuple[AnalysisResult, Optional[dict]]:
        t_start = time.perf_counter()
        investigation_id = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc).isoformat()

        checks: list[CheckPerformed] = []
        limitations = [
            "Static analysis cannot detect runtime behaviour, packed code, or dynamically loaded DEX.",
            "A clean result does not guarantee the app is safe – always install apps from official stores.",
            "The official-package list is curated and manually maintained.",
        ]

        # Size check
        if len(data) > self.settings.max_apk_bytes:
            verdict = Verdict.inconclusive
            result = AnalysisResult(
                investigation_id=investigation_id, type=ModuleType.apk, created_at=created_at,
                verdict=verdict, display_label=make_display_label("apk", verdict),
                summary=f"File exceeds {self.settings.MAX_APK_MB} MB limit.",
                checks_performed=[CheckPerformed(name="File size check", status=CheckStatus.failed,
                                                  detail="File too large.")],
                limitations=limitations, recommendations=standard_recommendations(verdict),
            )
            return result, None

        # Magic bytes / APK validity
        if not _is_valid_apk(data):
            checks.append(CheckPerformed(
                name="APK validity", status=CheckStatus.failed,
                detail="File is not a valid APK (missing ZIP magic or AndroidManifest.xml)."
            ))
            verdict = Verdict.inconclusive
            result = AnalysisResult(
                investigation_id=investigation_id, type=ModuleType.apk, created_at=created_at,
                verdict=verdict, display_label=make_display_label("apk", verdict),
                summary="The uploaded file is not a valid Android APK.",
                checks_performed=checks, limitations=limitations,
                recommendations=standard_recommendations(verdict),
            )
            return result, None

        checks.append(CheckPerformed(name="APK validity", status=CheckStatus.completed, detail="Valid APK format."))

        # Zip bomb check
        bomb_error = _check_zip_bomb(data)
        if bomb_error:
            checks.append(CheckPerformed(name="Zip bomb check", status=CheckStatus.failed, detail=bomb_error))
            verdict = Verdict.inconclusive
            result = AnalysisResult(
                investigation_id=investigation_id, type=ModuleType.apk, created_at=created_at,
                verdict=verdict, display_label=make_display_label("apk", verdict),
                summary=f"APK rejected: {bomb_error}",
                checks_performed=checks, limitations=limitations,
                recommendations=standard_recommendations(verdict),
            )
            return result, None

        checks.append(CheckPerformed(name="Zip bomb check", status=CheckStatus.completed, detail="OK."))

        sha256, md5 = _compute_hashes(data)
        file_size = len(data)

        # Parse APK – try androguard then pyaxmlparser then minimal
        parsed = _parse_with_androguard(data)
        parser_name = "androguard"
        if parsed is None:
            parsed = _parse_with_pyaxmlparser(data)
            parser_name = "pyaxmlparser"
        if parsed is None:
            parsed = _parse_minimal_zip(data)
            parser_name = "minimal_zip"

        if parsed is None:
            checks.append(CheckPerformed(
                name="Manifest parsing", status=CheckStatus.failed,
                detail="No parser could read this APK."
            ))
            verdict = Verdict.inconclusive
            result = AnalysisResult(
                investigation_id=investigation_id, type=ModuleType.apk, created_at=created_at,
                verdict=verdict, display_label=make_display_label("apk", verdict),
                summary="Could not parse the APK. The file may be corrupted or use an unsupported format.",
                checks_performed=checks, limitations=limitations,
                recommendations=standard_recommendations(verdict),
            )
            return result, None

        checks.append(CheckPerformed(
            name="Manifest parsing", status=CheckStatus.completed,
            detail=f"Parsed with {parser_name}. Package: {parsed.get('package_name', 'unknown')}"
        ))

        if parsed.get("parser") == "androguard":
            checks.append(CheckPerformed(
                name="DEX string scan",
                status=CheckStatus.completed,
                detail=f"Found {len(parsed.get('strings', []))} notable strings."
            ))
        else:
            checks.append(CheckPerformed(
                name="DEX string scan", status=CheckStatus.skipped,
                detail=f"DEX string scan requires androguard (used {parser_name})."
            ))

        # Apply rules
        evidence = _apply_apk_rules(parsed)
        checks.append(CheckPerformed(name="Security rules", status=CheckStatus.completed,
                                      detail=f"{len(evidence)} findings."))

        classified_perms = _classify_permissions(parsed.get("permissions", []))
        sensitive_perms = [p for p in classified_perms if p["severity"] in ("high", "medium")]
        embedded_urls = [s["value"] for s in parsed.get("strings", []) if s.get("type") == "url"]

        verdict = _decide_apk_verdict(evidence)
        display_label = make_display_label("apk", verdict)
        summary = _build_apk_summary(verdict, parsed, evidence, sensitive_perms)
        recommendations = standard_recommendations(verdict)

        result = AnalysisResult(
            investigation_id=investigation_id, type=ModuleType.apk, created_at=created_at,
            verdict=verdict, display_label=display_label, summary=summary,
            evidence=evidence, checks_performed=checks,
            limitations=limitations, recommendations=recommendations,
            analysis_version="1.0.0",
            input_summary=f"APK: {parsed.get('package_name', filename)} ({file_size // 1024} KB)",
        )

        apk_details = {
            "package_name": parsed.get("package_name"),
            "app_label": parsed.get("app_label"),
            "version_name": parsed.get("version_name"),
            "version_code": str(parsed.get("version_code") or ""),
            "sha256": sha256,
            "md5": md5,
            "file_size_bytes": file_size,
            "permissions": classified_perms,
            "sensitive_permissions": sensitive_perms,
            "embedded_urls": embedded_urls[:20],
            "min_sdk": parsed.get("min_sdk"),
            "target_sdk": parsed.get("target_sdk"),
        }

        return result, apk_details


def _build_apk_summary(verdict: Verdict, parsed: dict, evidence: list, sensitive_perms: list) -> str:
    pkg = parsed.get('package_name', 'unknown')
    if verdict == Verdict.malicious:
        high_evs = [e for e in evidence if e.severity == Severity.high]
        reason = high_evs[0].title if high_evs else "high-risk permission pattern"
        return f"App '{pkg}' shows a serious warning: {reason}. Do not install this app."
    if verdict == Verdict.suspicious:
        return (f"App '{pkg}' has {len(sensitive_perms)} sensitive permissions and "
                f"{len(evidence)} suspicious findings. Review carefully before installing.")
    return (f"No strong warning signs detected in '{pkg}'. "
            "Static analysis cannot detect runtime behaviour or packed code.")
