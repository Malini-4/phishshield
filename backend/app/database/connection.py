"""
Database connection setup with SQLAlchemy 2.x, WAL mode, and foreign keys enabled.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from contextlib import asynccontextmanager, contextmanager
from typing import Generator, AsyncGenerator

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    """SQLAlchemy declarative base for all models."""
    pass


def _get_sync_engine():
    settings = get_settings()
    url = settings.DATABASE_URL

    if url.startswith("sqlite:///./") or url.startswith("sqlite:///:memory:") is False and url.startswith("sqlite:///"):
        # Resolve path relative to project root
        db_path_str = url.replace("sqlite:///", "")
        if not os.path.isabs(db_path_str):
            # Project root is parent of backend directory
            project_root = Path(__file__).resolve().parent.parent.parent.parent
            abs_db_path = project_root / db_path_str
            abs_db_path.parent.mkdir(parents=True, exist_ok=True)
            url = f"sqlite:///{abs_db_path}"

    engine = create_engine(
        url,
        connect_args={"check_same_thread": False} if "sqlite" in url else {},
        echo=False,
    )

    @event.listens_for(engine, "connect")
    def set_sqlite_pragmas(dbapi_conn, connection_record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()

    return engine


_sync_engine = None
_SyncSession = None


def get_sync_engine():
    global _sync_engine
    if _sync_engine is None:
        _sync_engine = _get_sync_engine()
    return _sync_engine


def get_session_factory():
    global _SyncSession
    if _SyncSession is None:
        _SyncSession = sessionmaker(
            bind=get_sync_engine(),
            autocommit=False,
            autoflush=False,
            expire_on_commit=False,
        )
    return _SyncSession


@contextmanager
def get_db() -> Generator[Session, None, None]:
    """Provide a transactional scope around a series of operations."""
    factory = get_session_factory()
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db_dependency() -> Generator[Session, None, None]:
    """FastAPI dependency for database sessions."""
    factory = get_session_factory()
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db() -> None:
    """Create all tables (used for initial setup before Alembic migration)."""
    from app.database import models  # noqa: F401 - ensures models are registered
    engine = get_sync_engine()
    Base.metadata.create_all(engine)
    logger.info("Database tables initialised")


def check_db_health() -> bool:
    """Return True if the database is reachable and WAL mode is active."""
    try:
        engine = get_sync_engine()
        with engine.connect() as conn:
            result = conn.execute(text("PRAGMA journal_mode")).scalar()
            return result == "wal"
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return False
