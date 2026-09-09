"""Tests for resource protection: rate limiting and payload size caps."""

import pytest
from fastapi.testclient import TestClient

from sentinelcore.core.config import settings
from sentinelcore.core.limits import FixedWindowLimiter, client_key, get_limiter
from sentinelcore.main import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def _reset_limiter():
    get_limiter().reset()
    yield
    get_limiter().reset()


# --- limiter unit behaviour ---

def test_allows_up_to_the_limit_then_refuses():
    lim = FixedWindowLimiter(3, 60)
    assert [lim.check("c")[0] for _ in range(4)] == [True, True, True, False]


def test_rejected_requests_do_not_consume_budget():
    """A limited client must not be able to extend its own lockout by
    continuing to hammer the endpoint."""
    lim = FixedWindowLimiter(1, 60)
    lim.check("c")
    before = lim._counts["c"][0]
    for _ in range(10):
        lim.check("c")
    assert lim._counts["c"][0] == before


def test_clients_are_isolated():
    lim = FixedWindowLimiter(1, 60)
    lim.check("a")
    assert lim.check("b")[0] is True


def test_window_resets():
    lim = FixedWindowLimiter(1, 0)  # zero-length window: always expired
    assert lim.check("c")[0] is True
    assert lim.check("c")[0] is True


def test_api_key_preferred_over_ip_for_identity():
    """API key survives NAT and shared egress where IP does not."""
    assert client_key("secretkey123456789", "1.2.3.4").startswith("key:")
    assert client_key(None, "1.2.3.4") == "ip:1.2.3.4"
    assert client_key(None, None) == "ip:unknown"


def test_client_key_truncates_the_api_key():
    """The full key must not end up in limiter state or logs."""
    assert "secretkey123456789extra" not in client_key("secretkey123456789extra", None)


# --- middleware integration ---

def test_disabled_by_default():
    assert settings.rate_limit_enabled is False
    for _ in range(20):
        assert client.post("/api/v1/scan", json={"text": "hi"}).status_code == 200


def test_enforced_when_enabled(monkeypatch):
    monkeypatch.setattr(settings, "rate_limit_enabled", True)
    monkeypatch.setattr(settings, "rate_limit_requests", 3)
    get_limiter().reset()

    codes = [client.post("/api/v1/scan", json={"text": "hi"}).status_code for _ in range(5)]
    assert codes[:3] == [200, 200, 200]
    assert codes[3:] == [429, 429]


def test_429_carries_retry_after_and_limit_headers(monkeypatch):
    monkeypatch.setattr(settings, "rate_limit_enabled", True)
    monkeypatch.setattr(settings, "rate_limit_requests", 1)
    get_limiter().reset()

    client.post("/api/v1/scan", json={"text": "hi"})
    r = client.post("/api/v1/scan", json={"text": "hi"})
    assert r.status_code == 429
    assert int(r.headers["Retry-After"]) >= 1
    assert r.headers["X-RateLimit-Remaining"] == "0"
    assert r.json()["error"]["type"] == "sentinelcore_rate_limited"


def test_health_is_exempt(monkeypatch):
    """Rate-limiting health checks would let load convince an orchestrator
    that a healthy service is down -- turning protection into an outage."""
    monkeypatch.setattr(settings, "rate_limit_enabled", True)
    monkeypatch.setattr(settings, "rate_limit_requests", 1)
    get_limiter().reset()

    for _ in range(10):
        assert client.get("/api/v1/health").status_code == 200


def test_separate_api_keys_get_separate_budgets(monkeypatch):
    monkeypatch.setattr(settings, "rate_limit_enabled", True)
    monkeypatch.setattr(settings, "rate_limit_requests", 1)
    get_limiter().reset()

    assert client.post("/api/v1/scan", json={"text": "hi"}, headers={"X-API-Key": "a"}).status_code == 200
    assert client.post("/api/v1/scan", json={"text": "hi"}, headers={"X-API-Key": "a"}).status_code == 429
    assert client.post("/api/v1/scan", json={"text": "hi"}, headers={"X-API-Key": "b"}).status_code == 200


# --- payload size ---

def test_oversized_body_rejected(monkeypatch):
    monkeypatch.setattr(settings, "max_request_bytes", 500)
    r = client.post("/api/v1/scan", json={"text": "x" * 2000})
    assert r.status_code == 413
    assert r.json()["error"]["type"] == "sentinelcore_payload_too_large"


def test_normal_body_passes():
    assert client.post("/api/v1/scan", json={"text": "normal"}).status_code == 200


def test_size_cap_applies_even_when_rate_limiting_disabled(monkeypatch):
    """Size and rate are independent controls; one must not gate the other."""
    monkeypatch.setattr(settings, "rate_limit_enabled", False)
    monkeypatch.setattr(settings, "max_request_bytes", 100)
    assert client.post("/api/v1/scan", json={"text": "y" * 500}).status_code == 413
