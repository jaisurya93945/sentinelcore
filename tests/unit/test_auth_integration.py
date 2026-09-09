"""End-to-end tests confirming auth actually gates real endpoints."""

import httpx
import respx
from fastapi.testclient import TestClient

from sentinelcore.core.config import settings
from sentinelcore.main import app

client = TestClient(app)


def test_scan_works_without_key_when_auth_disabled():
    response = client.post("/api/v1/scan", json={"text": "hello"})
    assert response.status_code == 200


def test_scan_requires_key_when_auth_enabled(monkeypatch):
    monkeypatch.setattr(settings, "api_keys", "secret123:operator")
    response = client.post("/api/v1/scan", json={"text": "hello"})
    assert response.status_code == 401


def test_scan_succeeds_with_valid_operator_key(monkeypatch):
    monkeypatch.setattr(settings, "api_keys", "secret123:operator")
    response = client.post("/api/v1/scan", json={"text": "hello"}, headers={"X-API-Key": "secret123"})
    assert response.status_code == 200


def test_viewer_key_cannot_call_scan(monkeypatch):
    monkeypatch.setattr(settings, "api_keys", "viewkey:viewer")
    response = client.post("/api/v1/scan", json={"text": "hello"}, headers={"X-API-Key": "viewkey"})
    assert response.status_code == 403


def test_viewer_key_can_read_audit(monkeypatch):
    monkeypatch.setattr(settings, "api_keys", "viewkey:viewer")
    response = client.get("/api/v1/audit/recent", headers={"X-API-Key": "viewkey"})
    assert response.status_code == 200


def test_operator_key_also_inherits_viewer_access(monkeypatch):
    monkeypatch.setattr(settings, "api_keys", "opkey:operator")
    response = client.get("/api/v1/audit/recent", headers={"X-API-Key": "opkey"})
    assert response.status_code == 200


def test_health_endpoint_never_requires_auth(monkeypatch):
    monkeypatch.setattr(settings, "api_keys", "secret123:admin")
    response = client.get("/api/v1/health")
    assert response.status_code == 200


def test_dashboard_html_shell_never_requires_auth(monkeypatch):
    monkeypatch.setattr(settings, "api_keys", "secret123:admin")
    response = client.get("/dashboard")
    assert response.status_code == 200


def test_tool_call_requires_operator_role(monkeypatch):
    monkeypatch.setattr(settings, "api_keys", "opkey:operator")
    response = client.post(
        "/api/v1/scan/tool-call",
        json={"tool_name": "web.search", "arguments": {}},
        headers={"X-API-Key": "opkey"},
    )
    assert response.status_code == 200


def test_mcp_scan_requires_operator_role(monkeypatch):
    monkeypatch.setattr(settings, "api_keys", "opkey:operator")
    response = client.post(
        "/api/v1/scan/mcp-tools",
        json={"tools": [{"name": "t", "description": "fine", "inputSchema": {}}]},
        headers={"X-API-Key": "opkey"},
    )
    assert response.status_code == 200


@respx.mock
def test_proxy_requires_a_key_when_auth_enabled(monkeypatch):
    monkeypatch.setattr(settings, "api_keys", "opkey:operator")
    upstream_route = respx.post(f"{settings.upstream_base_url}/v1/chat/completions").mock(
        return_value=httpx.Response(200, json={"choices": [{"message": {"content": "hi"}}]})
    )
    response = client.post(
        "/v1/chat/completions",
        json={"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}]},
    )
    assert response.status_code == 401
    assert not upstream_route.called
