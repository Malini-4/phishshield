"""
Tests for the Case System:
1. Entity extraction and linkability filtering.
2. Tamper-evident ledger hash chain, verify_chain, and HMAC signing.
3. DB adapter with sqlite3.
4. Case creation, correlation via shared clues, and auto-grouping.
5. Case merging into oldest case with dual-ledger merge logging.
6. User data isolation / access control.
"""
import json
import sqlite3
import uuid

from app.cases.entities import extract_entities
from app.cases.ledger import (
    canonical_json,
    create_event_record,
    sign_head,
    verify_chain,
    verify_signature,
)
from app.cases.service import (
    add_note,
    get_case,
    list_cases,
    process_investigation,
    verify_case,
)
from app.cases.store import DBAdapter, init_case_tables


def create_in_memory_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    # Create required investigations table for test foreign keys / joins
    conn.execute("""
        CREATE TABLE investigations (
            id TEXT PRIMARY KEY,
            type TEXT NOT NULL,
            verdict TEXT NOT NULL,
            display_label TEXT,
            summary TEXT,
            input_display TEXT,
            duration_ms INTEGER,
            input_hash TEXT,
            result_json TEXT,
            details_json TEXT,
            user_id TEXT,
            created_at TEXT
        );
    """)
    init_case_tables(conn)
    return conn


def test_entity_extraction_and_linkability():
    # 1. Non-linkable: verified brand sender, big benign domain
    entities = extract_entities(
        module_type="sms",
        verdict="clean_no_findings",
        input_display="SMS from SBIINB",
        result_dict={"verdict": "clean_no_findings"},
        details_dict={"sender": "SBIINB", "sender_state": "exact_match", "extracted_urls": ["https://google.com"]},
    )
    for e in entities:
        if e["entity_type"] in ("sender_id", "domain"):
            assert e["linkable"] is False, f"Expected {e} to be non-linkable"

    # 2. Linkable: phone number, upi_id, 12-digit UTR, suspicious URL
    susp_entities = extract_entities(
        module_type="sms",
        verdict="suspicious",
        input_display="Urgent payment",
        result_dict={"verdict": "suspicious"},
        details_dict={
            "sender": "+919876543210",
            "sender_state": "malformed",
            "extracted_urls": ["https://fake-sbi-portal.xyz/login"],
            "redacted_text": "Send 5000 to fraud@okaxis with UTR 123456789012 call 9876543210",
        },
    )
    linkable_types = {e["entity_type"] for e in susp_entities if e["linkable"]}
    assert "phone" in linkable_types
    assert "upi_id" in linkable_types
    assert "domain" in linkable_types
    assert "url" in linkable_types


def test_ledger_hash_chain_and_tamper_detection():
    case_id = str(uuid.uuid4())
    zero_prev = "0" * 64

    # Build valid 3-event chain
    ev1 = create_event_record(case_id, 1, "case_created", {"title": "Test Case"}, zero_prev)
    ev2 = create_event_record(case_id, 2, "evidence_added", {"inv_id": "inv-1"}, ev1["record_hash"])
    ev3 = create_event_record(case_id, 3, "note_added", {"note": "Investigating"}, ev2["record_hash"])

    valid, broken_seq, detail = verify_chain([ev1, ev2, ev3])
    assert valid is True
    assert broken_seq is None

    # Tamper with event 2 payload
    tampered_ev2 = dict(ev2)
    tampered_ev2["payload"] = {"inv_id": "inv-1-tampered"}
    valid, broken_seq, detail = verify_chain([ev1, tampered_ev2, ev3])
    assert valid is False
    assert broken_seq == 2

    # Break hash linkage (wrong prev_hash)
    broken_ev3 = dict(ev3)
    broken_ev3["prev_hash"] = "f" * 64
    valid, broken_seq, detail = verify_chain([ev1, ev2, broken_ev3])
    assert valid is False
    assert broken_seq == 3


def test_ledger_hmac_signature():
    head_hash = "a" * 64
    key = "secret-key-123"
    sig = sign_head(head_hash, key)
    assert verify_signature(head_hash, sig, key) is True
    assert verify_signature(head_hash, sig, "wrong-key") is False


def test_case_correlation_groups_matching_investigations():
    conn = create_in_memory_db()
    user_id = "user-101"

    # Save investigation 1 (SMS with a scam UPI ID)
    inv1_id = "inv-sms-01"
    conn.execute(
        """
        INSERT INTO investigations (id, type, verdict, display_label, summary, user_id, created_at, result_json)
        VALUES (:id, 'sms', 'suspicious', 'Suspicious', 'Fake bill SMS', :uid, '2026-10-30T10:00:00Z', '{}')
        """,
        {"id": inv1_id, "uid": user_id},
    )
    res1 = {"type": "sms", "verdict": "suspicious", "input_summary": "SMS"}
    det1 = {
        "sender": "VK-ALERT",
        "sender_state": "unverified",
        "redacted_text": "Pay immediately to scammer@upi or power will be disconnected",
    }
    case_id_1 = process_investigation(conn, inv1_id, user_id, res1, det1)

    # Save investigation 2 (Screenshot of payment to the exact same scam UPI ID)
    inv2_id = "inv-screen-02"
    conn.execute(
        """
        INSERT INTO investigations (id, type, verdict, display_label, summary, user_id, created_at, result_json)
        VALUES (:id, 'screenshot', 'suspicious', 'Suspicious', 'Receipt', :uid, '2026-10-30T10:05:00Z', '{}')
        """,
        {"id": inv2_id, "uid": user_id},
    )
    res2 = {"type": "screenshot", "verdict": "suspicious", "input_summary": "Screenshot"}
    det2 = {
        "extracted_fields": {
            "upi_id": {"status": "read", "value": "scammer@upi"},
            "amount": {"status": "read", "value": "5000"},
            "status": {"status": "read", "value": "paid"},
        }
    }
    case_id_2 = process_investigation(conn, inv2_id, user_id, res2, det2)

    # Investigation 2 should join or form the case with Investigation 1
    assert case_id_2 is not None
    case_detail = get_case(conn, case_id_2, user_id)
    assert case_detail is not None
    member_ids = {m["investigation_id"] for m in case_detail["members"]}
    assert inv1_id in member_ids
    assert inv2_id in member_ids


def test_case_merging_into_oldest():
    conn = create_in_memory_db()
    user_id = "user-202"

    # Create Case A with phone clue
    inv_a1 = "inv-a1"
    inv_a2 = "inv-a2"
    conn.execute(
        "INSERT INTO investigations (id, type, verdict, user_id, created_at, result_json) VALUES (?, 'sms', 'suspicious', ?, '2026-10-30T09:00:00Z', '{}')",
        (inv_a1, user_id),
    )
    conn.execute(
        "INSERT INTO investigations (id, type, verdict, user_id, created_at, result_json) VALUES (?, 'sms', 'suspicious', ?, '2026-10-30T09:05:00Z', '{}')",
        (inv_a2, user_id),
    )
    process_investigation(conn, inv_a1, user_id, {"type": "sms", "verdict": "suspicious"}, {"sender": "9876543210", "sender_state": "malformed"})
    case_a = process_investigation(conn, inv_a2, user_id, {"type": "sms", "verdict": "suspicious"}, {"sender": "9876543210", "sender_state": "malformed"})
    assert case_a is not None

    # Create Case B with UPI clue
    inv_b1 = "inv-b1"
    inv_b2 = "inv-b2"
    conn.execute(
        "INSERT INTO investigations (id, type, verdict, user_id, created_at, result_json) VALUES (?, 'sms', 'suspicious', ?, '2026-10-30T09:10:00Z', '{}')",
        (inv_b1, user_id),
    )
    conn.execute(
        "INSERT INTO investigations (id, type, verdict, user_id, created_at, result_json) VALUES (?, 'sms', 'suspicious', ?, '2026-10-30T09:15:00Z', '{}')",
        (inv_b2, user_id),
    )
    process_investigation(conn, inv_b1, user_id, {"type": "sms", "verdict": "suspicious"}, {"redacted_text": "Pay to scam@paytm"})
    case_b = process_investigation(conn, inv_b2, user_id, {"type": "sms", "verdict": "suspicious"}, {"redacted_text": "Pay to scam@paytm"})
    assert case_b is not None
    assert case_a != case_b

    # Now an investigation C arrives that has BOTH the phone (from Case A) and the UPI (from Case B)
    inv_c = "inv-c"
    conn.execute(
        "INSERT INTO investigations (id, type, verdict, user_id, created_at, result_json) VALUES (?, 'sms', 'suspicious', ?, '2026-10-30T09:20:00Z', '{}')",
        (inv_c, user_id),
    )
    merged_case_id = process_investigation(
        conn,
        inv_c,
        user_id,
        {"type": "sms", "verdict": "suspicious"},
        {"sender": "9876543210", "sender_state": "malformed", "redacted_text": "Contact 9876543210 or pay scam@paytm"},
    )

    # Merged into oldest case (case_a)
    assert merged_case_id == case_a
    c_detail = get_case(conn, case_a, user_id)
    all_members = {m["investigation_id"] for m in c_detail["members"]}
    assert {inv_a1, inv_a2, inv_b1, inv_b2, inv_c}.issubset(all_members)


def test_user_access_isolation():
    conn = create_in_memory_db()
    user_a = "user-alice"
    user_b = "user-bob"

    # Alice has a case
    inv_a1 = "inv-a1"
    inv_a2 = "inv-a2"
    conn.execute("INSERT INTO investigations (id, type, verdict, user_id, created_at, result_json) VALUES (?, 'sms', 'suspicious', ?, '2026-10-30T10:00:00Z', '{}')", (inv_a1, user_a))
    conn.execute("INSERT INTO investigations (id, type, verdict, user_id, created_at, result_json) VALUES (?, 'sms', 'suspicious', ?, '2026-10-30T10:01:00Z', '{}')", (inv_a2, user_a))
    process_investigation(conn, inv_a1, user_a, {"type": "sms", "verdict": "suspicious"}, {"sender": "9876543210", "sender_state": "malformed"})
    alice_case_id = process_investigation(conn, inv_a2, user_a, {"type": "sms", "verdict": "suspicious"}, {"sender": "9876543210", "sender_state": "malformed"})
    assert alice_case_id is not None

    # Bob lists cases -> sees 0 cases
    bob_cases = list_cases(conn, user_b)
    assert len(bob_cases) == 0

    # Bob tries to get Alice's case directly -> None
    assert get_case(conn, alice_case_id, user_b) is None

    # Adding a note to Alice's case by Bob fails
    import pytest
    with pytest.raises(ValueError):
        add_note(conn, alice_case_id, user_b, "Hacked")
