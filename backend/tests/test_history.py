"""
Unit tests for database persistence, investigation history, and dashboard repository functions.
Uses an in-memory SQLite database for isolated test execution.
"""
import uuid
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.connection import Base
from app.database.models import Investigation
from app.database.repository import (
    save_investigation,
    get_history,
    get_investigation_by_id,
    delete_investigation,
    get_dashboard_stats,
)
from app.schemas.shared import AnalysisResult, ModuleType, Verdict


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()


def test_save_and_retrieve_investigation(db_session):
    inv_id = str(uuid.uuid4())
    result = AnalysisResult(
        investigation_id=inv_id,
        type=ModuleType.url,
        verdict=Verdict.malicious,
        display_label="Likely malicious",
        summary="A confirmed phishing URL was detected.",
        input_summary="URL: http://evil.com",
    )
    saved_id = save_investigation(db_session, result, module_details={"original_url": "http://evil.com"})
    assert saved_id == inv_id

    # Retrieve by ID
    record = get_investigation_by_id(db_session, inv_id)
    assert record is not None
    assert record["id"] == inv_id
    assert record["verdict"] == "malicious"
    assert record["type"] == "url"


def test_history_filtering_and_pagination(db_session):
    for i in range(15):
        v = Verdict.malicious if i % 2 == 0 else Verdict.clean_no_findings
        t = ModuleType.url if i < 10 else ModuleType.sms
        res = AnalysisResult(
            investigation_id=str(uuid.uuid4()),
            type=t,
            verdict=v,
            display_label="Test",
            summary=f"Item {i}",
            input_summary=f"Input {i}",
        )
        save_investigation(db_session, res, None)

    # Test pagination
    items, total = get_history(db_session, page=1, page_size=10)
    assert total == 15
    assert len(items) == 10

    # Test type filter
    sms_items, sms_total = get_history(db_session, type_filter="sms")
    assert sms_total == 5

    # Test verdict filter
    clean_items, clean_total = get_history(db_session, verdict_filter="clean_no_findings")
    assert clean_total == 7


def test_delete_investigation(db_session):
    inv_id = str(uuid.uuid4())
    res = AnalysisResult(
        investigation_id=inv_id,
        type=ModuleType.apk,
        verdict=Verdict.suspicious,
        display_label="Suspicious app",
        summary="Suspicious test app.",
        input_summary="APK: test.apk",
    )
    save_investigation(db_session, res, None)
    assert get_investigation_by_id(db_session, inv_id) is not None

    deleted = delete_investigation(db_session, inv_id)
    assert deleted is True
    assert get_investigation_by_id(db_session, inv_id) is None


def test_dashboard_stats(db_session):
    # Empty DB gives 0 totals
    empty_stats = get_dashboard_stats(db_session)
    assert empty_stats["total"] == 0

    # Add records
    res1 = AnalysisResult(
        investigation_id=str(uuid.uuid4()),
        type=ModuleType.url,
        verdict=Verdict.malicious,
        display_label="Malicious",
        summary="Sum",
        input_summary="Input",
    )
    save_investigation(db_session, res1, None)

    stats = get_dashboard_stats(db_session)
    assert stats["total"] == 1
    assert stats["by_type"]["url"] == 1
    assert stats["by_verdict"]["malicious"] == 1
