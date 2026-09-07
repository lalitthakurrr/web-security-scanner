import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.db.database import Base, engine

@pytest.fixture(autouse=True)
def setup_database():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

client = TestClient(app)

def test_api_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"

def test_create_and_list_scan():
    # 1. Post Scan
    response = client.post("/api/scans", json={"target_url": "http://127.0.0.1:8888", "max_depth": 1, "max_pages": 5})
    assert response.status_code == 202
    scan_data = response.json()
    assert scan_data["target_url"] == "http://127.0.0.1:8888"
    scan_id = scan_data["id"]

    # 2. List Scans
    list_resp = client.get("/api/scans")
    assert list_resp.status_code == 200
    scans = list_resp.json()
    assert any(s["id"] == scan_id for s in scans)

def test_stats_endpoint():
    response = client.get("/api/stats")
    assert response.status_code == 200
    data = response.json()
    assert "total_scans" in data
    assert "avg_security_score" in data


def test_scan_rejects_invalid_url_random_word():
    """Random words with no dots must be rejected with HTTP 422."""
    response = client.post("/api/scans", json={"target_url": "djaska"})
    assert response.status_code == 422, f"Expected 422, got {response.status_code}: {response.text}"
    assert "valid domain" in response.json()["detail"].lower() or "dot" in response.json()["detail"].lower()


def test_scan_rejects_empty_url():
    """Empty URL must be rejected."""
    response = client.post("/api/scans", json={"target_url": ""})
    assert response.status_code == 422


def test_scan_rejects_url_with_no_dot():
    """URL with no dot in hostname (like 'http://garbage') must be rejected."""
    response = client.post("/api/scans", json={"target_url": "http://garbage"})
    assert response.status_code == 422
    assert "dot" in response.json()["detail"].lower() or "valid domain" in response.json()["detail"].lower()
