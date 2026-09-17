"""Tests for GET /dashboard and detail propagation into the audit trail."""

from fastapi.testclient import TestClient

from sentinelcore.main import app

client = TestClient(app)


def test_dashboard_route_returns_html():
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "SentinelCore" in response.text
    # The endpoint moved into dashboard.js when the script was split out so
    # the page could carry script-src 'self'.
    assert 'src="/static/dashboard.js"' in response.text


def test_dashboard_never_embeds_raw_scan_text():
    response = client.get("/dashboard")
    assert "ignore all previous instructions" not in response.text.lower()


def test_tool_call_detail_reaches_audit_trail():
    from sentinelcore.services.audit_log import get_recent_events

    client.post(
        "/api/v1/scan/tool-call",
        json={"tool_name": "database.delete", "arguments": {"table": "logs"}},
    )
    events = get_recent_events(limit=1)
    assert events[0]["detail"] == "database.delete"


def test_mcp_tool_detail_reaches_audit_trail():
    from sentinelcore.services.audit_log import get_recent_events

    client.post(
        "/api/v1/scan/mcp-tools",
        json={"tools": [{"name": "my_custom_tool", "description": "fine", "inputSchema": {}}]},
    )
    events = get_recent_events(limit=1)
    assert events[0]["detail"] == "my_custom_tool"


def test_plain_scan_has_no_detail():
    from sentinelcore.services.audit_log import get_recent_events

    client.post("/api/v1/scan", json={"text": "hello"})
    events = get_recent_events(limit=1)
    assert events[0]["detail"] is None


# --- XSS regression -----------------------------------------------------
#
# A stored XSS shipped in the previous dashboard: a tool name was
# interpolated into innerHTML unescaped, so any caller who could reach
# /scan/tool-call could attack the admin viewing the page -- a page that
# holds an API key. These tests exist so it cannot come back.

def test_dashboard_script_never_uses_innerhtml():
    """The structural fix. Untrusted values are built with createElement and
    createTextNode; a single innerHTML assignment would reopen the hole."""
    import re
    from pathlib import Path

    js = (Path(__file__).parent.parent.parent / "sentinelcore" / "static" / "dashboard.js").read_text()
    code = "\n".join(line.split("//")[0] for line in js.splitlines() if not line.strip().startswith("*"))
    assert not re.search(r"\.innerHTML\s*=", code), "innerHTML assignment reintroduced"
    assert not re.search(r"insertAdjacentHTML|document\.write|outerHTML\s*=", code)


def test_dashboard_carries_a_strict_csp():
    """Defence in depth: a missed escape must not be able to execute."""
    r = client.get("/dashboard")
    csp = r.headers["content-security-policy"]
    assert "script-src 'self'" in csp
    assert "'unsafe-inline'" not in csp.split("script-src")[1].split(";")[0], (
        "script-src must not permit inline execution"
    )
    assert "frame-ancestors 'none'" in csp
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["cache-control"] == "no-store"


def test_dashboard_html_has_no_inline_script():
    """An inline script would force script-src to allow 'unsafe-inline',
    which defeats the CSP as an XSS control."""
    assert "<script>" not in client.get("/dashboard").text


def test_attacker_controlled_tool_name_is_not_reflected_into_markup():
    """End-to-end: a hostile tool name is stored, but the page that renders
    it contains no markup derived from it."""
    payload = '<img src=x onerror="alert(1)">'
    client.post("/api/v1/scan/tool-call", json={"tool_name": payload, "arguments": {}})
    events = client.get("/api/v1/audit/recent?limit=5").json()["events"]
    assert any(e.get("detail") == payload for e in events), "payload should be stored verbatim"
    assert payload not in client.get("/dashboard").text, "payload reflected into the dashboard"


def test_script_is_served_with_nosniff():
    r = client.get("/static/dashboard.js")
    assert r.status_code == 200
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "javascript" in r.headers["content-type"]


def test_api_key_is_not_persisted_beyond_the_session():
    """localStorage would outlive the tab; an operator's key should not."""
    from pathlib import Path

    js = (Path(__file__).parent.parent.parent / "sentinelcore" / "static" / "dashboard.js").read_text()
    # Strip comments before checking: the file explains WHY localStorage is
    # avoided, and a naive substring match flags that explanation. This is
    # the second time a comment-blind assertion of mine produced a false
    # failure, so both checks now strip first.
    code = "\n".join(line.split("//")[0] for line in js.splitlines() if not line.strip().startswith("*"))
    assert "localStorage" not in code, "the API key must not outlive the tab"
    assert "sessionStorage" in code


def test_dashboard_surfaces_every_operator_facing_subsystem():
    """Built capability that the operator cannot reach is not shipped."""
    html = client.get("/dashboard").text
    for tab in ("activity", "approvals", "mcp", "health"):
        assert f'data-tab="{tab}"' in html
