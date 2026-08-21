"""Tests for GET /dashboard and detail propagation into the audit trail."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_dashboard_route_returns_html():
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "SentinelCore" in response.text
    assert "/api/v1/audit/recent" in response.text  # confirms it polls the real endpoint


def test_dashboard_never_embeds_raw_scan_text():
    """The page itself must not hardcode or leak any example input text --
    it's a template that fetches data at runtime, nothing more."""
    response = client.get("/dashboard")
    assert "ignore all previous instructions" not in response.text.lower()


def test_tool_call_detail_reaches_audit_trail():
    from app.services.audit_log import get_recent_events

    client.post(
        "/api/v1/scan/tool-call",
        json={"tool_name": "database.delete", "arguments": {"table": "logs"}},
    )
    events = get_recent_events(limit=1)
    assert events[0]["detail"] == "database.delete"


def test_mcp_tool_detail_reaches_audit_trail():
    from app.services.audit_log import get_recent_events

    client.post(
        "/api/v1/scan/mcp-tools",
        json={"tools": [{"name": "my_custom_tool", "description": "fine", "inputSchema": {}}]},
    )
    events = get_recent_events(limit=1)
    assert events[0]["detail"] == "my_custom_tool"


def test_plain_scan_has_no_detail():
    from app.services.audit_log import get_recent_events

    client.post("/api/v1/scan", json={"text": "hello"})
    events = get_recent_events(limit=1)
    assert events[0]["detail"] is None
