from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_check():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["service"] == "SentinelCore"


def test_root():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["service"] == "SentinelCore"
