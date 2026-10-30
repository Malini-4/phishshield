"""SMS text normalization, shorthand expansion, and sender header parsing."""
from __future__ import annotations

import re
from typing import Optional


def expand_shorthand(text: str) -> str:
    """
    Turns SMS shorthand into standard English/terminology:
    ur/yr -> your, u -> you, pls/plz -> please, a/c, acc, acct -> account,
    k y c / k.y.c -> kyc, adhar/aadhar -> aadhaar, txn -> transaction,
    blkd -> blocked, updt -> update.
    """
    if not text:
        return ""

    t = text

    # 'k y c' or 'k.y.c' with optional spaces/dots
    t = re.sub(r"(?i)\bk[\s.]*y[\s.]*c\b", "kyc", t)

    # a/c, acc, acct -> account
    t = re.sub(r"(?i)\ba/c\b", "account", t)
    t = re.sub(r"(?i)\bacc(?:t)?\b", "account", t)

    # ur / yr -> your
    t = re.sub(r"(?i)\b(?:ur|yr)\b", "your", t)

    # u -> you
    t = re.sub(r"(?i)\bu\b", "you", t)

    # pls / plz -> please
    t = re.sub(r"(?i)\b(?:pls|plz)\b", "please", t)

    # adhar / aadhar -> aadhaar
    t = re.sub(r"(?i)\b(?:adhar|aadhar)\b", "aadhaar", t)

    # txn -> transaction
    t = re.sub(r"(?i)\btxn\b", "transaction", t)

    # blkd -> blocked
    t = re.sub(r"(?i)\bblkd\b", "blocked", t)

    # updt -> update
    t = re.sub(r"(?i)\bupdt\b", "update", t)

    return t


def split_sender(raw: Optional[str]) -> str:
    """
    Returns the core DLT header from:
    - 'VK-SBIINB' -> 'SBIINB'
    - 'vk SBIINB' -> 'SBIINB'
    - 'SBIINB'    -> 'SBIINB'
    - 'VK_SBIINB' -> 'SBIINB'
    - 'VKHDFCBK'  -> 'HDFCBK' (8-character glued form: 2-char prefix + 6-char header)
    A 2-3 letter prefix may be separated by '-', '_' or a space.
    Removes inner spaces and converts to uppercase.
    """
    if not raw or not raw.strip():
        return ""

    s = raw.strip()
    m = re.match(r"^([a-zA-Z]{2,3})[-\s_]+([a-zA-Z0-9\s]+)$", s)
    if m:
        return m.group(2).replace(" ", "").upper()

    cleaned = s.replace(" ", "").upper()
    # 8-character glued form: 2-letter operator/circle prefix + 6-letter commercial DLT header
    if len(cleaned) == 8 and cleaned.isalpha():
        return cleaned[2:]

    return cleaned


def normalise_for_model(text: str) -> str:
    """
    Normalise SMS text for machine learning:
    shorthand expanded, URLs replaced by 'urltoken', numbers by 'numtoken'.
    """
    if not text:
        return ""

    t = expand_shorthand(text)

    # Replace URLs and links
    t = re.sub(r"https?://\S+|hxxps?://\S+|www\.\S+", "urltoken", t, flags=re.IGNORECASE)
    t = re.sub(
        r"\b[a-zA-Z0-9.\-]+\.(?:com|org|net|in|co\.in|gov\.in|xyz|top|app|dev|me|site|live|click|link|cc|work|info|biz|online|store|tech|club|vip)(?:/\S*)?",
        "urltoken",
        t,
        flags=re.IGNORECASE,
    )
    t = re.sub(r"\[obfuscated-shortener\]|\b(?:bit|tinyurl|is|goo|cutt)\s*[\[\(\.\s\]\)]+\s*(?:ly|gl|com|co)\S*", "urltoken", t, flags=re.IGNORECASE)

    # Replace numbers, currency amounts, OTPs, phone numbers
    t = re.sub(r"\b\d[\d,.]*\b|\b\d+\b", "numtoken", t)

    # Normalize whitespace
    t = re.sub(r"\s+", " ", t).strip()

    return t
