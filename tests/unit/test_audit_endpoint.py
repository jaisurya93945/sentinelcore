"""Tests for GET /api/v1/audit/recent."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_audit_recent_returns_events_after_a_scan():
    client.post("/api/v1/scan", json={"text": "some text to scan for the audit endpoint test"})
    response = client.get("/api/v1/audit/recent?limit=5")
    assert response.status_code == 200
    body = response.json()
    assert "events" in body
    assert len(body["events"]) >= 1


def test_audit_recent_empty_before_any_scan():
    response = client.get("/api/v1/audit/recent?limit=5")
    assert response.status_code == 200
    assert response.json()["events"] == []


def test_audit_recent_limit_is_bounded():
    response = client.get("/api/v1/audit/recent?limit=99999")
    assert response.status_code == 422  # exceeds the 500 max, rejected not silently clamped
