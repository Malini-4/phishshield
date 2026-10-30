"""Database adapter and table schema for the case system."""
from __future__ import annotations

import json
import sqlite3
import uuid
from typing import Any, Dict, List, Optional, Union

from sqlalchemy import text
from sqlalchemy.orm import Session

CREATE_CASES_TABLE = """
CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    risk_level TEXT NOT NULL DEFAULT 'suspicious',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""

CREATE_CASE_MEMBERS_TABLE = """
CREATE TABLE IF NOT EXISTS case_members (
    case_id TEXT NOT NULL,
    investigation_id TEXT NOT NULL,
    added_at TEXT NOT NULL,
    result_hash TEXT NOT NULL,
    PRIMARY KEY (case_id, investigation_id)
);
"""

CREATE_INV_ENTITIES_TABLE = """
CREATE TABLE IF NOT EXISTS inv_entities (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_value TEXT NOT NULL,
    linkable INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
"""

CREATE_CASE_EVENTS_TABLE = """
CREATE TABLE IF NOT EXISTS case_events (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    ts TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    record_hash TEXT NOT NULL,
    UNIQUE (case_id, seq)
);
"""


class DBAdapter:
    """Unified adapter supporting both sqlite3.Connection and SQLAlchemy Session."""

    def __init__(self, db: Union[sqlite3.Connection, Session, DBAdapter]):
        if isinstance(db, DBAdapter):
            self.db = db.db
            self.is_session = db.is_session
        elif isinstance(db, Session):
            self.db = db
            self.is_session = True
        else:
            self.db = db
            self.is_session = False
            # Ensure row factory is sqlite3.Row for dict conversions
            if hasattr(db, "row_factory") and db.row_factory is None:
                db.row_factory = sqlite3.Row

    def execute(self, sql: str, params: Optional[Dict[str, Any]] = None) -> None:
        p = params or {}
        if self.is_session:
            self.db.execute(text(sql), p)
        else:
            self.db.execute(sql, p)

    def fetchall(self, sql: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        p = params or {}
        if self.is_session:
            result = self.db.execute(text(sql), p)
            return [dict(r._mapping) for r in result.fetchall()]
        else:
            cur = self.db.execute(sql, p)
            rows = cur.fetchall()
            return [dict(r) for r in rows]

    def fetchone(self, sql: str, params: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        p = params or {}
        if self.is_session:
            result = self.db.execute(text(sql), p)
            row = result.fetchone()
            return dict(row._mapping) if row else None
        else:
            cur = self.db.execute(sql, p)
            row = cur.fetchone()
            return dict(row) if row else None

    def commit(self) -> None:
        if self.is_session:
            self.db.commit()
        else:
            self.db.commit()


def init_case_tables(db: Optional[Union[sqlite3.Connection, Session, DBAdapter]] = None) -> None:
    """Initialize case database tables if they do not exist."""
    if db is None:
        from app.database.connection import engine
        with engine.begin() as conn:
            conn.execute(text(CREATE_CASES_TABLE))
            conn.execute(text(CREATE_CASE_MEMBERS_TABLE))
            conn.execute(text(CREATE_INV_ENTITIES_TABLE))
            conn.execute(text(CREATE_CASE_EVENTS_TABLE))
        return

    adapter = DBAdapter(db)
    adapter.execute(CREATE_CASES_TABLE)
    adapter.execute(CREATE_CASE_MEMBERS_TABLE)
    adapter.execute(CREATE_INV_ENTITIES_TABLE)
    adapter.execute(CREATE_CASE_EVENTS_TABLE)
    adapter.commit()
