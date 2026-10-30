"""Tamper-evident ledger hash chain and cryptographic verification."""
from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

GENESIS_PREV_HASH = "0" * 64


def canonical_json(data: Any) -> str:
    """Format data as canonical JSON with sorted keys and compact separators."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_record_hash(
    case_id: str,
    seq: int,
    ts: str,
    event_type: str,
    payload: Dict[str, Any],
    prev_hash: str,
) -> str:
    """Compute SHA-256 over the canonical representation of event fields."""
    record_obj = {
        "case_id": case_id,
        "event_type": event_type,
        "payload": payload,
        "prev_hash": prev_hash,
        "seq": seq,
        "ts": ts,
    }
    canonical = canonical_json(record_obj).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def create_event_record(
    case_id: str,
    seq: int,
    event_type: str,
    payload: Dict[str, Any],
    prev_hash: str,
    ts: Optional[str] = None,
) -> Dict[str, Any]:
    """Construct an event record with its deterministic SHA-256 hash."""
    if ts is None:
        ts = datetime.now(timezone.utc).isoformat()
    record_hash = compute_record_hash(case_id, seq, ts, event_type, payload, prev_hash)
    return {
        "case_id": case_id,
        "seq": seq,
        "ts": ts,
        "event_type": event_type,
        "payload": payload,
        "prev_hash": prev_hash,
        "record_hash": record_hash,
    }


def verify_chain(events: List[Dict[str, Any]]) -> Tuple[bool, Optional[int], Optional[str]]:
    """
    Verify the cryptographic integrity of a ledger chain.
    Returns: (is_valid, broken_seq, error_message)
    Returns the FIRST broken record index/seq if invalid.
    """
    if not events:
        return True, None, None

    for i, ev in enumerate(events):
        seq = ev.get("seq")
        expected_seq = i + 1
        if seq != expected_seq:
            return False, seq, f"Sequence error: expected {expected_seq}, got {seq} (reordered or deleted record)"

        prev_hash = ev.get("prev_hash")
        if seq == 1:
            if prev_hash != GENESIS_PREV_HASH:
                return False, 1, f"Genesis record must have prev_hash of 64 zeros, got {prev_hash}"
        else:
            expected_prev = events[i - 1].get("record_hash")
            if prev_hash != expected_prev:
                return False, seq, f"Broken link at seq {seq}: prev_hash does not match previous record_hash"

        # Re-compute record hash
        payload = ev.get("payload")
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except Exception:
                pass
        if not isinstance(payload, dict):
            payload = {}

        expected_hash = compute_record_hash(
            case_id=ev.get("case_id", ""),
            seq=seq,
            ts=ev.get("ts", ""),
            event_type=ev.get("event_type", ""),
            payload=payload,
            prev_hash=prev_hash,
        )
        if ev.get("record_hash") != expected_hash:
            return False, seq, f"Tampered record at seq {seq}: record_hash mismatch"

    return True, None, None


def sign_head(head_hash: str, secret_key: Optional[str] = None) -> str:
    """Sign the head hash using HMAC-SHA256."""
    if not secret_key:
        from app.config import get_settings
        settings = get_settings()
        secret_key = getattr(settings, "CASE_SIGNING_KEY", None) or getattr(settings, "JWT_SECRET_KEY", "phishshield-signing-key")
    return hmac.new(secret_key.encode("utf-8"), head_hash.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_signature(head_hash: str, signature: str, secret_key: Optional[str] = None) -> bool:
    """Verify the HMAC-SHA256 signature of a head hash."""
    if not signature or not head_hash:
        return False
    expected = sign_head(head_hash, secret_key)
    return hmac.compare_digest(expected, signature)
