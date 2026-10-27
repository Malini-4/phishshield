"""
URL Parser – safe, no network calls.
Parses and normalises URLs for feature extraction and rule checking.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import struct
import unicodedata
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional

import tldextract

logger = logging.getLogger(__name__)

# tldextract with bundled suffix list – no network at runtime
_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())

ALLOWED_SCHEMES = {"http", "https"}

MAX_URL_LENGTH = 2048
CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")


@dataclass
class ParsedUrl:
    original_input: str
    normalised: str
    scheme: str
    userinfo: Optional[str]
    host: str  # raw host (may include port removed already)
    port: Optional[int]
    path: str
    query: str
    fragment: str
    registrable_domain: str
    subdomain: str
    domain: str
    suffix: str
    is_ip: bool
    ip_form: Optional[str]  # decimal | hex | octal | ipv6 | None
    ip_address: Optional[str]  # normalised dotted-decimal
    is_idna: bool  # any label starts with xn--
    is_mixed_script: bool
    labels: list[str]  # hostname labels
    scheme_was_missing: bool = False
    double_encoding_detected: bool = False
    notes: list[str] = field(default_factory=list)


@dataclass
class ValidationError:
    code: str
    message: str
    field: str = "url"


def _is_mixed_script(hostname: str) -> bool:
    """Detect hostnames mixing different Unicode script categories."""
    scripts: set[str] = set()
    for ch in hostname:
        if ch in ".-":
            continue
        try:
            name = unicodedata.name(ch, "")
            if "LATIN" in name:
                scripts.add("LATIN")
            elif "CYRILLIC" in name:
                scripts.add("CYRILLIC")
            elif "GREEK" in name:
                scripts.add("GREEK")
            elif "DEVANAGARI" in name:
                scripts.add("DEVANAGARI")
            elif "ARABIC" in name:
                scripts.add("ARABIC")
            elif "CJK" in name or "HIRAGANA" in name or "KATAKANA" in name:
                scripts.add("CJK")
        except Exception:
            pass
    return len(scripts) > 1


def _parse_ip_host(host: str) -> tuple[bool, Optional[str], Optional[str]]:
    """
    Returns (is_ip, ip_form, normalised_ip_string).
    Handles: dotted decimal, hex (0x...), octal (0...), packed decimal (single large int), IPv6.
    """
    h = host.strip("[]")  # strip IPv6 brackets

    # IPv6
    try:
        addr = ipaddress.IPv6Address(h)
        return True, "ipv6", str(addr)
    except ValueError:
        pass

    # Standard dotted decimal
    try:
        addr = ipaddress.IPv4Address(h)
        return True, "decimal", str(addr)
    except ValueError:
        pass

    # Hex: 0x7f000001
    if re.match(r"^0x[0-9a-fA-F]{1,8}$", h):
        try:
            val = int(h, 16)
            addr = ipaddress.IPv4Address(val)
            return True, "hex", str(addr)
        except Exception:
            pass

    # Octal: 0177.0.0.01 or single octal number
    if re.match(r"^0[0-7]+$", h):
        try:
            val = int(h, 8)
            addr = ipaddress.IPv4Address(val)
            return True, "octal", str(addr)
        except Exception:
            pass

    # Packed decimal: single large number
    if re.match(r"^\d+$", h):
        try:
            val = int(h)
            if 0 <= val <= 0xFFFFFFFF:
                addr = ipaddress.IPv4Address(val)
                return True, "decimal_packed", str(addr)
        except Exception:
            pass

    # Mixed-base dotted notation (e.g. 0x7f.0.0.1, 0177.0.0.1)
    if "." in h:
        parts = h.split(".")
        if len(parts) == 4:
            decoded = []
            for p in parts:
                try:
                    if p.startswith("0x") or p.startswith("0X"):
                        decoded.append(int(p, 16))
                    elif p.startswith("0") and len(p) > 1:
                        decoded.append(int(p, 8))
                    else:
                        decoded.append(int(p, 10))
                except ValueError:
                    break
            else:
                if all(0 <= x <= 255 for x in decoded):
                    return True, "mixed_base", ".".join(str(x) for x in decoded)

    return False, None, None


def _detect_double_encoding(url: str) -> bool:
    """Detect percent-encoded percent signs (%25xx) indicating double encoding."""
    return bool(re.search(r"%25[0-9a-fA-F]{2}", url))


def parse_url(raw_input: str) -> ParsedUrl | ValidationError:
    """
    Parse and normalise a URL string for analysis.
    Returns ParsedUrl on success or ValidationError on rejection.
    Does NOT make any network calls.
    """
    # 1. Basic validation
    stripped = raw_input.strip()
    if not stripped:
        return ValidationError("EMPTY_INPUT", "URL cannot be empty.")
    if len(stripped) > MAX_URL_LENGTH:
        return ValidationError(
            "TOO_LONG",
            f"URL exceeds maximum length of {MAX_URL_LENGTH} characters.",
        )
    if CONTROL_CHAR_RE.search(stripped):
        return ValidationError(
            "CONTROL_CHARS",
            "URL contains control characters and cannot be analysed.",
        )

    scheme_was_missing = False
    working = stripped

    # 2. Check scheme
    if "://" not in working:
        # Check for blocked scheme prefixes
        for blocked in ("javascript:", "data:", "file:", "ftp:", "mailto:", "vbscript:"):
            if working.lower().startswith(blocked):
                return ValidationError(
                    "BLOCKED_SCHEME",
                    f"The scheme '{blocked.rstrip(':')}' is not supported. Only http and https URLs can be analysed.",
                )
        # Assume http:// if missing
        working = "http://" + working
        scheme_was_missing = True
    else:
        scheme_lower = working.split("://")[0].lower()
        if scheme_lower not in ALLOWED_SCHEMES:
            return ValidationError(
                "BLOCKED_SCHEME",
                f"The scheme '{scheme_lower}' is not supported. Only http and https URLs can be analysed.",
            )

    # 3. Replace backslashes (common obfuscation)
    working = working.replace("\\", "/")

    # 4. Detect double encoding
    double_enc = _detect_double_encoding(working)

    # 5. Parse with urllib
    try:
        parsed = urllib.parse.urlparse(working)
    except Exception as e:
        return ValidationError("PARSE_ERROR", f"Could not parse URL: {e}")

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc
    path = parsed.path
    query = parsed.query
    fragment = parsed.fragment

    # 6. Extract userinfo (@ trick)
    userinfo: Optional[str] = None
    host_port = netloc
    if "@" in netloc:
        userinfo, host_port = netloc.rsplit("@", 1)

    # 7. Split host and port
    port: Optional[int] = None
    host = host_port
    if host_port.startswith("["):
        # IPv6 – find closing bracket
        bracket_end = host_port.find("]")
        if bracket_end != -1:
            host = host_port[: bracket_end + 1]
            rest = host_port[bracket_end + 1 :]
            if rest.startswith(":"):
                try:
                    port = int(rest[1:])
                except ValueError:
                    pass
    elif ":" in host_port:
        parts = host_port.rsplit(":", 1)
        host = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            pass

    if not host:
        return ValidationError("NO_HOST", "URL does not contain a valid host.")

    # 8. IP detection
    is_ip, ip_form, ip_addr = _parse_ip_host(host)

    # 9. IDN / punycode
    is_idna = any(label.lower().startswith("xn--") for label in host.split("."))

    # 10. Mixed script detection (on decoded form)
    try:
        decoded_host = host.encode("ascii").decode("idna") if is_idna else host
    except Exception:
        decoded_host = host
    is_mixed = _is_mixed_script(decoded_host)

    # 11. tldextract on clean host (no port, no brackets)
    clean_host = host.strip("[]").rstrip(".")
    ext = _EXTRACTOR(clean_host)
    registrable = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else clean_host
    subdomain = ext.subdomain or ""
    domain = ext.domain or ""
    suffix = ext.suffix or ""

    labels = [l for l in clean_host.split(".") if l]

    # 12. Build normalised URL for display
    normalised = urllib.parse.urlunparse((scheme, netloc, path, "", query, ""))

    notes: list[str] = []
    if scheme_was_missing:
        notes.append("Scheme was not specified; assumed http:// for analysis.")
    if double_enc:
        notes.append("Double percent-encoding detected in URL.")
    if userinfo:
        notes.append("URL contains userinfo (@) in the authority – common phishing trick.")

    return ParsedUrl(
        original_input=stripped,
        normalised=normalised,
        scheme=scheme,
        userinfo=userinfo,
        host=clean_host,
        port=port,
        path=path,
        query=query,
        fragment=fragment,
        registrable_domain=registrable.lower(),
        subdomain=subdomain.lower(),
        domain=domain.lower(),
        suffix=suffix.lower(),
        is_ip=is_ip,
        ip_form=ip_form,
        ip_address=ip_addr,
        is_idna=is_idna,
        is_mixed_script=is_mixed,
        labels=labels,
        scheme_was_missing=scheme_was_missing,
        double_encoding_detected=double_enc,
        notes=notes,
    )
