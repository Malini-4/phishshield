"""
SQLAlchemy ORM models for PhishShield.
All tables use UUID primary keys and include created_at timestamps.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.connection import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_uuid() -> str:
    return str(uuid.uuid4())


class Investigation(Base):
    """Main record for any analysis performed."""
    __tablename__ = "investigations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    user_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)  # nullable for legacy records
    type: Mapped[str] = mapped_column(String(20), nullable=False, index=True)  # url|apk|sms|screenshot
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    verdict: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    display_label: Mapped[str] = mapped_column(String(80), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    input_display: Mapped[str] = mapped_column(Text, nullable=False)  # safe/redacted display
    input_hash: Mapped[str] = mapped_column(String(64), nullable=False)  # SHA-256 of original
    analysis_version: Mapped[str] = mapped_column(String(20), nullable=False, default="1.0.0")
    model_version: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="completed")  # completed|failed_partial
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    result_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Relationships
    evidence_items: Mapped[list["EvidenceItem"]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan"
    )
    checks: Mapped[list["CheckRecord"]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan"
    )
    url_details: Mapped[Optional["UrlDetails"]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan", uselist=False
    )
    apk_details: Mapped[Optional["ApkDetails"]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan", uselist=False
    )
    sms_details: Mapped[Optional["SmsDetails"]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan", uselist=False
    )
    screenshot_details: Mapped[Optional["ScreenshotDetails"]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan", uselist=False
    )

    __table_args__ = (
        Index("ix_investigations_type_verdict", "type", "verdict"),
        Index("ix_investigations_created_type", "created_at", "type"),
        Index("ix_investigations_user_created", "user_id", "created_at"),
    )


class EvidenceItem(Base):
    """Individual evidence points for an investigation."""
    __tablename__ = "evidence_items"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    investigation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    category: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[str] = mapped_column(String(10), nullable=False)  # info|low|medium|high
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    detail: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(30), nullable=False)  # model|rule|reputation|parser|ocr

    investigation: Mapped["Investigation"] = relationship(back_populates="evidence_items")


class CheckRecord(Base):
    """Record of each check performed during analysis."""
    __tablename__ = "checks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    investigation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)  # completed|failed|unavailable|skipped
    detail: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    investigation: Mapped["Investigation"] = relationship(back_populates="checks")


class UrlDetails(Base):
    """URL-specific details for a URL investigation."""
    __tablename__ = "url_details"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    investigation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    original_url: Mapped[str] = mapped_column(Text, nullable=False)
    registrable_domain: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    scheme: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)
    host: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    model_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    model_band: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    reputation_results: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    rule_hits: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    features_summary: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    investigation: Mapped["Investigation"] = relationship(back_populates="url_details")


class ApkDetails(Base):
    """APK-specific details."""
    __tablename__ = "apk_details"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    investigation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    package_name: Mapped[Optional[str]] = mapped_column(String(300), nullable=True)
    app_label: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    version_name: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    version_code: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    md5: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    file_size_bytes: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    permissions: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    sensitive_permissions: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    embedded_urls: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    min_sdk: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)
    target_sdk: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)

    investigation: Mapped["Investigation"] = relationship(back_populates="apk_details")


class SmsDetails(Base):
    """SMS-specific details."""
    __tablename__ = "sms_details"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    investigation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    sender: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    sender_state: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    message_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    redacted_text: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    extracted_urls: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    message_length: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    investigation: Mapped["Investigation"] = relationship(back_populates="sms_details")


class ScreenshotDetails(Base):
    """Screenshot-specific details."""
    __tablename__ = "screenshot_details"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    investigation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    file_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    file_size_bytes: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    image_width: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    image_height: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    ocr_engine: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    ocr_confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    extracted_fields: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    investigation: Mapped["Investigation"] = relationship(back_populates="screenshot_details")


class ReputationFeedEntry(Base):
    """Local cache of reputation feed entries (OpenPhish, URLhaus)."""
    __tablename__ = "reputation_feed_entries"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    source: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    url_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # may be omitted for privacy
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    entry_meta: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    __table_args__ = (
        Index("ix_feed_source_hash", "source", "url_hash"),
    )


class FeedStatus(Base):
    """Tracks the last successful feed refresh per source."""
    __tablename__ = "feed_status"

    source: Mapped[str] = mapped_column(String(30), primary_key=True)
    last_success_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    record_count: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class AppMeta(Base):
    """Application metadata (schema version etc.)."""
    __tablename__ = "app_meta"

    key: Mapped[str] = mapped_column(String(50), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
