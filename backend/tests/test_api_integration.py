"""
FastAPI integration tests using an isolated temporary database.
Verifies all REST API routes, error responses, security headers, and PDF export.
"""
import io
import zipfile
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.database.connection import Base, get_db_dependency


# Setup isolated in-memory test database for API tests
@pytest.fixture(scope="module")
def client():
    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(test_engine)
    TestingSession = sessionmaker(bind=test_engine)

    def override_get_db():
        db = TestingSession()
        try:
            yield db
            db.commit()
        finally:
            db.close()

    app.dependency_overrides[get_db_dependency] = override_get_db

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


def test_health_endpoint(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] in ("ok", "degraded")
    assert "model_loaded" in data
    assert "reputation_sources" in data


def test_security_headers_present(client):
    resp = client.get("/api/health")
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"


def test_url_analyze_api(client):
    resp = client.post("/api/url/analyze", json={"url": "https://netbanking.hdfcbank.com/netbanking/"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["type"] == "url"
    assert "verdict" in data
    assert "display_label" in data
    assert "evidence" in data
    assert data["saved"] is True


def test_url_invalid_error_envelope(client):
    resp = client.post("/api/url/analyze", json={"url": "javascript:alert(1)"})
    assert resp.status_code == 422
    data = resp.json()
    assert "error" in data["detail"]
    assert "code" in data["detail"]["error"]


def test_sms_analyze_api(client):
    resp = client.post(
        "/api/sms/analyze",
        json={
            "message": "Your OTP is 482910. Do not share this OTP with anyone.",
            "sender": "HDFCBK"
        }
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["type"] == "sms"
    assert "verdict" in data
    assert data["saved"] is True


def test_apk_analyze_api(client):
    # Create minimal synthetic APK in memory
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("AndroidManifest.xml", b"<manifest package='com.test.app'></manifest>")
        z.writestr("classes.dex", b"dex\n035\x00data")

    resp = client.post(
        "/api/apk/analyze",
        files={"file": ("test.apk", buf.getvalue(), "application/vnd.android.package-archive")}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["type"] == "apk"
    assert data["saved"] is True


def test_auth_and_history_isolation_flow(client):
    # 1. Unauthenticated history access is rejected
    unauth_resp = client.get("/api/history")
    assert unauth_resp.status_code == 401

    # 2. Register User A
    user_a_payload = {
        "full_name": "Alice Officer",
        "email": "alice@shield.org",
        "password": "Password123!",
        "confirm_password": "Password123!",
    }
    reg_a = client.post("/api/auth/register", json=user_a_payload)
    assert reg_a.status_code == 201
    token_a = reg_a.json()["access_token"]
    headers_a = {"Authorization": f"Bearer {token_a}"}

    # 3. Duplicate email registration is rejected (case-insensitive)
    dup_payload = dict(user_a_payload, email="ALICE@shield.org")
    reg_dup = client.post("/api/auth/register", json=dup_payload)
    assert reg_dup.status_code == 409

    # 4. Incorrect credentials login is rejected
    bad_login = client.post("/api/auth/login", json={"email": "alice@shield.org", "password": "WrongPassword"})
    assert bad_login.status_code == 401

    # 5. Correct credentials login succeeds
    good_login = client.post("/api/auth/login", json={"email": "alice@shield.org", "password": "Password123!"})
    assert good_login.status_code == 200
    assert "access_token" in good_login.json()

    # 6. Current user endpoint
    me_resp = client.get("/api/auth/me", headers=headers_a)
    assert me_resp.status_code == 200
    assert me_resp.json()["email"] == "alice@shield.org"

    # 7. User A performs an analysis while authenticated
    scan_resp = client.post(
        "/api/url/analyze",
        json={"url": "https://secure-login.test-phish.xyz"},
        headers=headers_a,
    )
    assert scan_resp.status_code == 200
    inv_id = scan_resp.json()["investigation_id"]

    # 8. User A can see their own investigation in history
    hist_a = client.get("/api/history", headers=headers_a)
    assert hist_a.status_code == 200
    a_items = hist_a.json()["items"]
    assert any(item["id"] == inv_id for item in a_items)

    # 9. User A can retrieve their report and download PDF
    rep_a = client.get(f"/api/history/{inv_id}", headers=headers_a)
    assert rep_a.status_code == 200

    pdf_resp = client.get(f"/api/history/{inv_id}/export.pdf", headers=headers_a)
    assert pdf_resp.status_code == 200
    assert pdf_resp.headers["content-type"] == "application/pdf"
    assert len(pdf_resp.content) > 100

    # 10. Register User B
    user_b_payload = {
        "full_name": "Bob Analyst",
        "email": "bob@shield.org",
        "password": "Password123!",
        "confirm_password": "Password123!",
    }
    reg_b = client.post("/api/auth/register", json=user_b_payload)
    assert reg_b.status_code == 201
    token_b = reg_b.json()["access_token"]
    headers_b = {"Authorization": f"Bearer {token_b}"}

    # 11. User B's history is isolated and does NOT contain User A's investigation
    hist_b = client.get("/api/history", headers=headers_b)
    assert hist_b.status_code == 200
    b_items = hist_b.json()["items"]
    assert not any(item["id"] == inv_id for item in b_items)

    # 12. User B cannot access User A's individual report (ownership check)
    forbidden_rep = client.get(f"/api/history/{inv_id}", headers=headers_b)
    assert forbidden_rep.status_code == 404  # Not found for User B

    # 13. User B cannot export User A's PDF
    forbidden_pdf = client.get(f"/api/history/{inv_id}/export.pdf", headers=headers_b)
    assert forbidden_pdf.status_code == 404

    # 14. User B cannot delete User A's report
    forbidden_del = client.delete(f"/api/history/{inv_id}", headers=headers_b)
    assert forbidden_del.status_code == 404

    # 15. Dashboard stats are scoped to the user
    dash_a = client.get("/api/dashboard/stats", headers=headers_a)
    assert dash_a.status_code == 200
    assert dash_a.json()["total"] >= 1

    dash_b = client.get("/api/dashboard/stats", headers=headers_b)
    assert dash_b.status_code == 200
    assert dash_b.json()["total"] == 0
