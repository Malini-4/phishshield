"""Case management service: investigation grouping, graph building, and integrity verification."""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Union

from app.cases.entities import extract_entities
from app.cases.ledger import (
    canonical_json,
    create_event_record,
    sign_head,
    verify_chain,
    verify_signature,
)
from app.cases.store import DBAdapter, init_case_tables


def compute_result_hash(result_dict: Dict[str, Any]) -> str:
    """Compute deterministic SHA-256 over canonical result JSON."""
    cjson = canonical_json(result_dict).encode("utf-8")
    return hashlib.sha256(cjson).hexdigest()


def append_case_event(
    adapter: DBAdapter,
    case_id: str,
    event_type: str,
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    """Append a cryptographically chained event to case_events."""
    row = adapter.fetchone(
        "SELECT seq, record_hash FROM case_events WHERE case_id = :case_id ORDER BY seq DESC LIMIT 1",
        {"case_id": case_id},
    )
    if row:
        seq = row["seq"] + 1
        prev_hash = row["record_hash"]
    else:
        seq = 1
        prev_hash = "0" * 64

    ts = datetime.now(timezone.utc).isoformat()
    ev = create_event_record(case_id, seq, event_type, payload, prev_hash, ts=ts)
    adapter.execute(
        """
        INSERT INTO case_events (id, case_id, seq, ts, event_type, payload_json, prev_hash, record_hash)
        VALUES (:id, :case_id, :seq, :ts, :event_type, :payload_json, :prev_hash, :record_hash)
        """,
        {
            "id": str(uuid.uuid4()),
            "case_id": case_id,
            "seq": ev["seq"],
            "ts": ev["ts"],
            "event_type": ev["event_type"],
            "payload_json": json.dumps(ev["payload"], ensure_ascii=True),
            "prev_hash": ev["prev_hash"],
            "record_hash": ev["record_hash"],
        },
    )
    return ev


def create_new_case(
    adapter: DBAdapter,
    user_id: str,
    title: str,
    risk_level: str = "suspicious",
) -> str:
    """Create a new case and initialize its event ledger."""
    case_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    adapter.execute(
        """
        INSERT INTO cases (id, user_id, title, status, risk_level, created_at, updated_at)
        VALUES (:id, :user_id, :title, 'open', :risk_level, :created_at, :updated_at)
        """,
        {
            "id": case_id,
            "user_id": user_id,
            "title": title,
            "risk_level": risk_level,
            "created_at": now,
            "updated_at": now,
        },
    )
    append_case_event(adapter, case_id, "case_created", {
        "case_id": case_id,
        "title": title,
        "user_id": user_id,
        "created_at": now,
    })
    return case_id


def attach_investigation_to_case(
    adapter: DBAdapter,
    case_id: str,
    inv_id: str,
    inv_type: str,
    result_dict: Dict[str, Any],
    extra_payload: Optional[Dict[str, Any]] = None,
) -> None:
    """Attach an investigation to a case and log an evidence_added event."""
    existing = adapter.fetchone(
        "SELECT 1 FROM case_members WHERE case_id = :case_id AND investigation_id = :inv_id",
        {"case_id": case_id, "inv_id": inv_id},
    )
    if existing:
        return

    res_hash = compute_result_hash(result_dict)
    now = datetime.now(timezone.utc).isoformat()
    adapter.execute(
        """
        INSERT INTO case_members (case_id, investigation_id, added_at, result_hash)
        VALUES (:case_id, :inv_id, :added_at, :result_hash)
        """,
        {
            "case_id": case_id,
            "inv_id": inv_id,
            "added_at": now,
            "result_hash": res_hash,
        },
    )

    payload: Dict[str, Any] = {
        "investigation_id": inv_id,
        "type": inv_type,
        "result_hash": res_hash,
        "added_at": now,
    }
    if extra_payload:
        payload.update(extra_payload)

    append_case_event(adapter, case_id, "evidence_added", payload)


def merge_cases(adapter: DBAdapter, target_case_id: str, source_case_id: str) -> None:
    """Merge source_case into target_case and record in both ledgers."""
    if target_case_id == source_case_id:
        return

    members = adapter.fetchall(
        "SELECT investigation_id, added_at, result_hash FROM case_members WHERE case_id = :source_case_id",
        {"source_case_id": source_case_id},
    )
    for m in members:
        inv_id = m["investigation_id"]
        existing = adapter.fetchone(
            "SELECT 1 FROM case_members WHERE case_id = :target_case_id AND investigation_id = :inv_id",
            {"target_case_id": target_case_id, "inv_id": inv_id},
        )
        if not existing:
            adapter.execute(
                """
                INSERT INTO case_members (case_id, investigation_id, added_at, result_hash)
                VALUES (:target_case_id, :inv_id, :added_at, :result_hash)
                """,
                {
                    "target_case_id": target_case_id,
                    "inv_id": inv_id,
                    "added_at": m["added_at"],
                    "result_hash": m["result_hash"],
                },
            )
            append_case_event(adapter, target_case_id, "evidence_added", {
                "investigation_id": inv_id,
                "result_hash": m["result_hash"],
                "merged_from_case": source_case_id,
            })

    # Record merge event in target ledger
    append_case_event(adapter, target_case_id, "cases_merged", {
        "target_case_id": target_case_id,
        "source_case_id": source_case_id,
        "role": "target",
    })

    # Record merge event in source ledger
    append_case_event(adapter, source_case_id, "cases_merged", {
        "target_case_id": target_case_id,
        "source_case_id": source_case_id,
        "role": "source",
    })

    # Mark source case as merged
    now = datetime.now(timezone.utc).isoformat()
    adapter.execute(
        """
        UPDATE cases SET status = :status, updated_at = :updated_at WHERE id = :source_case_id
        """,
        {
            "status": f"merged_into_{target_case_id}",
            "updated_at": now,
            "source_case_id": source_case_id,
        },
    )


def recalculate_case_risk(adapter: DBAdapter, case_id: str) -> None:
    """Recalculate case risk level from member investigation verdicts."""
    members = adapter.fetchall(
        """
        SELECT i.verdict FROM case_members cm
        JOIN investigations i ON cm.investigation_id = i.id
        WHERE cm.case_id = :case_id
        """,
        {"case_id": case_id},
    )
    verdicts = {m["verdict"] for m in members if m.get("verdict")}
    if "malicious" in verdicts:
        risk = "malicious"
    elif "suspicious" in verdicts:
        risk = "suspicious"
    elif "inconclusive" in verdicts:
        risk = "inconclusive"
    else:
        risk = "clean_no_findings"

    now = datetime.now(timezone.utc).isoformat()
    adapter.execute(
        "UPDATE cases SET risk_level = :risk, updated_at = :updated_at WHERE id = :case_id",
        {"risk": risk, "updated_at": now, "case_id": case_id},
    )


def process_investigation(
    db: Any,
    investigation_id: str,
    user_id: str,
    result_dict: Dict[str, Any],
    details_dict: Optional[Dict[str, Any]] = None,
    target_case_id: Optional[str] = None,
) -> Optional[str]:
    """
    Core entrypoint: extracts entities, joins or opens cases, and logs evidence.
    """
    if not user_id:
        return None

    adapter = DBAdapter(db)
    init_case_tables(adapter)

    inv_type = result_dict.get("type", "unknown")
    verdict = result_dict.get("verdict", "unknown")
    input_display = result_dict.get("input_summary", "")

    # 1. Extract entities
    entities = extract_entities(inv_type, verdict, input_display, result_dict, details_dict)

    now = datetime.now(timezone.utc).isoformat()
    # 2. Save entities
    for ent in entities:
        adapter.execute(
            """
            INSERT INTO inv_entities (id, investigation_id, user_id, entity_type, entity_value, linkable, created_at)
            VALUES (:id, :inv_id, :user_id, :etype, :evalue, :linkable, :created_at)
            """,
            {
                "id": str(uuid.uuid4()),
                "inv_id": investigation_id,
                "user_id": user_id,
                "etype": ent["entity_type"],
                "evalue": ent["entity_value"],
                "linkable": 1 if ent["linkable"] else 0,
                "created_at": now,
            },
        )

    # If explicit target_case_id provided (e.g. from SMS auto-analysed link)
    if target_case_id:
        attach_investigation_to_case(adapter, target_case_id, investigation_id, inv_type, result_dict)
        recalculate_case_risk(adapter, target_case_id)
        adapter.commit()
        return target_case_id

    # 3. Find matching open cases for this user via linkable entities
    linkables = [e for e in entities if e["linkable"]]
    matching_cases: List[Dict[str, Any]] = []

    if linkables:
        # Check matching entities from other investigations of this user
        placeholders = []
        for i, ent in enumerate(linkables):
            p_type = f"et_{i}"
            p_val = f"ev_{i}"
            placeholders.append(f"(ie.entity_type = :{p_type} AND ie.entity_value = :{p_val})")

        sql_params: Dict[str, Any] = {"user_id": user_id, "curr_inv_id": investigation_id}
        for i, ent in enumerate(linkables):
            sql_params[f"et_{i}"] = ent["entity_type"]
            sql_params[f"ev_{i}"] = ent["entity_value"]

        where_cond = " OR ".join(placeholders)

        # Query existing open cases containing matching investigations
        cases_sql = f"""
        SELECT DISTINCT c.id, c.created_at, c.title
        FROM cases c
        JOIN case_members cm ON c.id = cm.case_id
        JOIN inv_entities ie ON cm.investigation_id = ie.investigation_id
        WHERE c.user_id = :user_id
          AND c.status = 'open'
          AND ie.user_id = :user_id
          AND ie.linkable = 1
          AND ie.investigation_id != :curr_inv_id
          AND ({where_cond})
        ORDER BY c.created_at ASC
        """
        matching_cases = adapter.fetchall(cases_sql, sql_params)

    # 4. Handle Case Joining or Merging
    if matching_cases:
        oldest_case = matching_cases[0]
        case_id = oldest_case["id"]

        # If multiple cases match, merge them into the oldest
        for other in matching_cases[1:]:
            merge_cases(adapter, case_id, other["id"])

        attach_investigation_to_case(adapter, case_id, investigation_id, inv_type, result_dict)
        recalculate_case_risk(adapter, case_id)
        adapter.commit()
        return case_id

    # 5. Check if matches earlier uncased investigations
    if linkables:
        uncased_sql = f"""
        SELECT DISTINCT ie.investigation_id
        FROM inv_entities ie
        LEFT JOIN case_members cm ON ie.investigation_id = cm.investigation_id
        WHERE ie.user_id = :user_id
          AND ie.linkable = 1
          AND ie.investigation_id != :curr_inv_id
          AND cm.case_id IS NULL
          AND ({where_cond})
        """
        uncased_invs = adapter.fetchall(uncased_sql, sql_params)
        if uncased_invs:
            # Open a new case grouping earlier uncased investigations and this one!
            first_match_val = linkables[0]["entity_value"]
            title = f"Case: {linkables[0]['entity_type'].upper()} {first_match_val[:24]}"
            case_id = create_new_case(adapter, user_id, title, risk_level=verdict)

            # Attach earlier uncased investigations
            for u in uncased_invs:
                u_id = u["investigation_id"]
                # Fetch investigation details from DB
                inv_row = adapter.fetchone("SELECT type, result_json FROM investigations WHERE id = :id", {"id": u_id})
                u_type = inv_row["type"] if inv_row else "unknown"
                u_res = {}
                if inv_row and inv_row.get("result_json"):
                    try:
                        u_res = json.loads(inv_row["result_json"]) if isinstance(inv_row["result_json"], str) else inv_row["result_json"]
                    except Exception:
                        pass
                attach_investigation_to_case(adapter, case_id, u_id, u_type, u_res)

            attach_investigation_to_case(adapter, case_id, investigation_id, inv_type, result_dict)
            recalculate_case_risk(adapter, case_id)
            adapter.commit()
            return case_id

    # 6. Check if this investigation is a suspicious SMS with links
    if inv_type == "sms" and (details_dict or {}).get("extracted_urls"):
        if verdict in ("suspicious", "malicious"):
            sender = (details_dict or {}).get("sender") or "SMS"
            title = f"Case: Suspicious SMS ({sender})"
            case_id = create_new_case(adapter, user_id, title, risk_level=verdict)
            attach_investigation_to_case(adapter, case_id, investigation_id, inv_type, result_dict)
            adapter.commit()
            return case_id

    adapter.commit()
    return None


def list_cases(db: Any, user_id: str) -> List[Dict[str, Any]]:
    """List open cases belonging to user_id."""
    adapter = DBAdapter(db)
    init_case_tables(adapter)

    cases = adapter.fetchall(
        """
        SELECT id, title, status, risk_level, created_at, updated_at
        FROM cases
        WHERE user_id = :user_id AND status = 'open'
        ORDER BY updated_at DESC
        """,
        {"user_id": user_id},
    )

    for c in cases:
        cid = c["id"]
        # Member counts & distinct types
        members = adapter.fetchall(
            """
            SELECT i.type FROM case_members cm
            JOIN investigations i ON cm.investigation_id = i.id
            WHERE cm.case_id = :case_id
            """,
            {"case_id": cid},
        )
        c["item_count"] = len(members)
        c["modules"] = list(dict.fromkeys(m["type"] for m in members if m.get("type")))

    return cases


def get_case(db: Any, case_id: str, user_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve full case details, graph nodes/edges, ledger events, and clues."""
    adapter = DBAdapter(db)
    init_case_tables(adapter)

    case_row = adapter.fetchone(
        "SELECT * FROM cases WHERE id = :case_id AND user_id = :user_id",
        {"case_id": case_id, "user_id": user_id},
    )
    if not case_row:
        return None

    # Fetch members with investigation info
    members_raw = adapter.fetchall(
        """
        SELECT cm.investigation_id, cm.added_at, cm.result_hash,
               i.type, i.verdict, i.display_label, i.summary, i.input_display, i.created_at
        FROM case_members cm
        LEFT JOIN investigations i ON cm.investigation_id = i.id
        WHERE cm.case_id = :case_id
        ORDER BY cm.added_at ASC
        """,
        {"case_id": case_id},
    )

    member_ids = [m["investigation_id"] for m in members_raw]

    # Fetch entities for these members
    clues_by_entity: Dict[tuple[str, str], List[str]] = {}
    if member_ids:
        in_params = {f"id_{i}": mid for i, mid in enumerate(member_ids)}
        in_clause = ", ".join(f":id_{i}" for i in range(len(member_ids)))
        ent_rows = adapter.fetchall(
            f"""
            SELECT investigation_id, entity_type, entity_value, linkable
            FROM inv_entities
            WHERE investigation_id IN ({in_clause})
            """,
            in_params,
        )
        for r in ent_rows:
            key = (r["entity_type"], r["entity_value"])
            if key not in clues_by_entity:
                clues_by_entity[key] = []
            if r["investigation_id"] not in clues_by_entity[key]:
                clues_by_entity[key].append(r["investigation_id"])

    # Clues list
    clues_list = []
    for (etype, evalue), invs in clues_by_entity.items():
        clues_list.append({
            "entity_type": etype,
            "entity_value": evalue,
            "count": len(invs),
            "investigation_ids": invs,
            "is_shared": len(invs) >= 2,
        })
    clues_list.sort(key=lambda x: (not x["is_shared"], -x["count"], x["entity_type"]))

    # Graph Nodes and Edges
    nodes = []
    edges = []

    # Evidence nodes
    for m in members_raw:
        mid = m["investigation_id"]
        inp = m.get("input_display") or ""
        mtype = m.get("type") or "evidence"
        nodes.append({
            "id": mid,
            "label": f"{mtype.upper()}: {inp[:20]}",
            "type": "evidence",
            "module_type": mtype,
            "verdict": m.get("verdict", "unknown"),
        })

    # Clue nodes and edges
    for idx, c in enumerate(clues_list):
        clue_id = f"clue_{idx}"
        nodes.append({
            "id": clue_id,
            "label": f"{c['entity_type']}: {c['entity_value']}",
            "type": "clue",
            "entity_type": c["entity_type"],
            "entity_value": c["entity_value"],
            "is_shared": c["is_shared"],
        })
        for mid in c["investigation_ids"]:
            edges.append({
                "source": mid,
                "target": clue_id,
            })

    # Fetch events
    events_raw = adapter.fetchall(
        """
        SELECT seq, ts, event_type, payload_json, prev_hash, record_hash
        FROM case_events
        WHERE case_id = :case_id
        ORDER BY seq ASC
        """,
        {"case_id": case_id},
    )
    events = []
    notes = []
    for ev in events_raw:
        try:
            p = json.loads(ev["payload_json"])
        except Exception:
            p = {}
        ev_obj = {
            "seq": ev["seq"],
            "ts": ev["ts"],
            "event_type": ev["event_type"],
            "payload": p,
            "prev_hash": ev["prev_hash"],
            "record_hash": ev["record_hash"],
        }
        events.append(ev_obj)
        if ev["event_type"] == "note_added":
            notes.append({
                "seq": ev["seq"],
                "ts": ev["ts"],
                "text": p.get("text", ""),
                "user_id": p.get("user_id"),
            })

    head_hash = events[-1]["record_hash"] if events else ("0" * 64)
    signature = sign_head(head_hash)

    return {
        "id": case_row["id"],
        "title": case_row["title"],
        "status": case_row["status"],
        "risk_level": case_row["risk_level"],
        "created_at": case_row["created_at"],
        "updated_at": case_row["updated_at"],
        "head_hash": head_hash,
        "signature": signature,
        "members": members_raw,
        "clues": clues_list,
        "graph": {
            "nodes": nodes,
            "edges": edges,
        },
        "events": events,
        "notes": notes,
    }


def verify_case(db: Any, case_id: str, user_id: str) -> Dict[str, Any]:
    """Verify cryptographic chain, head signature, and evidence re-fingerprints."""
    adapter = DBAdapter(db)
    init_case_tables(adapter)

    case_row = adapter.fetchone(
        "SELECT * FROM cases WHERE id = :case_id AND user_id = :user_id",
        {"case_id": case_id, "user_id": user_id},
    )
    if not case_row:
        return {"status": "tampered", "problems": ["Case not found or unauthorized"]}

    problems: List[str] = []

    # 1. Verify event chain
    events_raw = adapter.fetchall(
        "SELECT seq, ts, event_type, payload_json, prev_hash, record_hash FROM case_events WHERE case_id = :case_id ORDER BY seq ASC",
        {"case_id": case_id},
    )
    events = []
    for r in events_raw:
        try:
            p = json.loads(r["payload_json"])
        except Exception:
            p = {}
        events.append({
            "case_id": case_id,
            "seq": r["seq"],
            "ts": r["ts"],
            "event_type": r["event_type"],
            "payload": p,
            "prev_hash": r["prev_hash"],
            "record_hash": r["record_hash"],
        })

    chain_ok, broken_seq, reason = verify_chain(events)
    if not chain_ok:
        problems.append(f"Ledger hash chain broken at record #{broken_seq}: {reason}")

    # 2. Check head signature
    head_hash = events[-1]["record_hash"] if events else ("0" * 64)
    sig = sign_head(head_hash)
    sig_ok = verify_signature(head_hash, sig)
    if not sig_ok:
        problems.append("Head hash cryptographic signature verification failed.")

    # 3. Re-fingerprint each stored investigation result
    members = adapter.fetchall(
        "SELECT investigation_id, result_hash FROM case_members WHERE case_id = :case_id",
        {"case_id": case_id},
    )
    member_statuses = []
    for m in members:
        inv_id = m["investigation_id"]
        expected_hash = m["result_hash"]
        inv_row = adapter.fetchone("SELECT result_json FROM investigations WHERE id = :id", {"id": inv_id})
        if not inv_row or not inv_row.get("result_json"):
            member_statuses.append({"investigation_id": inv_id, "status": "missing"})
            problems.append(f"Investigation {inv_id} result record is missing.")
            continue

        raw_json = inv_row["result_json"]
        try:
            r_dict = json.loads(raw_json) if isinstance(raw_json, str) else raw_json
        except Exception:
            r_dict = {}

        current_hash = compute_result_hash(r_dict)
        if current_hash != expected_hash:
            member_statuses.append({"investigation_id": inv_id, "status": "modified"})
            problems.append(f"Investigation {inv_id} content modified: hash mismatch.")
        else:
            member_statuses.append({"investigation_id": inv_id, "status": "ok"})

    is_intact = len(problems) == 0

    return {
        "status": "intact" if is_intact else "tampered",
        "chain_valid": chain_ok,
        "broken_seq": broken_seq,
        "head_hash": head_hash,
        "signature_valid": sig_ok,
        "members": member_statuses,
        "problems": problems,
    }


def add_note(db: Any, case_id: str, user_id: str, text: str) -> Dict[str, Any]:
    """Add an investigator note to the case ledger."""
    adapter = DBAdapter(db)
    init_case_tables(adapter)

    case_row = adapter.fetchone(
        "SELECT * FROM cases WHERE id = :case_id AND user_id = :user_id",
        {"case_id": case_id, "user_id": user_id},
    )
    if not case_row:
        raise ValueError("Case not found or unauthorized.")

    now = datetime.now(timezone.utc).isoformat()
    ev = append_case_event(adapter, case_id, "note_added", {
        "text": text,
        "user_id": user_id,
        "added_at": now,
    })
    adapter.execute(
        "UPDATE cases SET updated_at = :updated_at WHERE id = :case_id",
        {"updated_at": now, "case_id": case_id},
    )
    adapter.commit()
    return ev
