"""Unit tests for API key authentication and role-based authorization."""

import pytest
from fastapi import HTTPException

from sentinelcore.core.auth import Role, parse_api_keys, require_role
from sentinelcore.core.config import settings


def test_no_keys_configured_means_auth_disabled(monkeypatch):
    monkeypatch.setattr(settings, "api_keys", "")
    assert parse_api_keys() == {}


def test_parses_key_role_pairs(monkeypatch):
    monkeypatch.setattr(settings, "api_keys", "abc123:viewer,def456:operator,ghi789:admin")
    keys = parse_api_keys()
    assert keys["abc123"] == Role.VIEWER
    assert keys["def456"] == Role.OPERATOR
    assert keys["ghi789"] == Role.ADMIN


def test_unrecognized_role_is_skipped_not_granted(monkeypatch):
    monkeypatch.setattr(settings, "api_keys", "abc123:superuser")
    assert parse_api_keys() == {}


def test_malformed_entries_ignored(monkeypatch):
    monkeypatch.setattr(settings, "api_keys", "no-colon-here,,  ,abc:viewer")
    assert parse_api_keys() == {"abc": Role.VIEWER}


def test_require_role_allows_through_when_auth_disabled(monkeypatch):
    monkeypatch.setattr(settings, "api_keys", "")
    require_role(Role.ADMIN)(x_api_key=None)


def test_require_role_rejects_missing_key_when_auth_enabled(monkeypatch):
    monkeypatch.setattr(settings, "api_keys", "abc123:viewer")
    with pytest.raises(HTTPException) as exc_info:
        require_role(Role.VIEWER)(x_api_key=None)
    assert exc_info.value.status_code == 401


def test_require_role_rejects_invalid_key(monkeypatch):
    monkeypatch.setattr(settings, "api_keys", "abc123:viewer")
    with pytest.raises(HTTPException) as exc_info:
        require_role(Role.VIEWER)(x_api_key="wrong-key")
    assert exc_info.value.status_code == 401


def test_require_role_rejects_insufficient_role(monkeypatch):
    monkeypatch.setattr(settings, "api_keys", "viewer-key:viewer")
    with pytest.raises(HTTPException) as exc_info:
        require_role(Role.OPERATOR)(x_api_key="viewer-key")
    assert exc_info.value.status_code == 403


def test_require_role_allows_higher_role_through(monkeypatch):
    monkeypatch.setattr(settings, "api_keys", "admin-key:admin")
    require_role(Role.OPERATOR)(x_api_key="admin-key")


def test_require_role_allows_exact_role(monkeypatch):
    monkeypatch.setattr(settings, "api_keys", "op-key:operator")
    require_role(Role.OPERATOR)(x_api_key="op-key")


# --- unauthenticated exposure -------------------------------------------
#
# Auth is off by default and that default was documented. A note in a
# repository is not a runtime control: the shipped Dockerfile binds
# 0.0.0.0:8000, so `docker run` produced a gateway whose own security
# controls were open. Measured with no keys configured, GET
# /api/v1/mcp/pins and GET /api/v1/audit/recent both returned data to an
# anonymous caller, and the role checks that would stop someone re-pinning
# an MCP baseline or deciding a pending approval were skipped entirely.
#
# Nothing told the operator. These cover what now does.


from sentinelcore.core import auth as auth_mod


@pytest.fixture
def env():
    """Restores the real settings; these tests mutate global config."""
    before = (settings.environment, settings.api_keys, settings.allow_unauthenticated)
    yield settings
    settings.environment, settings.api_keys, settings.allow_unauthenticated = before


def test_exposure_is_reported_when_no_keys_are_configured(env):
    env.api_keys = ""
    msg = auth_mod.unauthenticated_exposure()
    assert msg is not None
    # Naming what is reachable is the point; "auth is disabled" tells an
    # operator nothing about whether it matters to them.
    assert "audit log" in msg and "SENTINELCORE_API_KEYS" in msg


def test_no_exposure_reported_once_keys_exist(env):
    env.api_keys = "k1:admin"
    assert auth_mod.unauthenticated_exposure() is None


def test_development_warns_but_starts(env):
    """Running without keys locally is deliberate and convenient, so this
    must stay a warning -- a hard failure here would break the documented
    default and every quickstart."""
    env.environment, env.api_keys = "development", ""
    auth_mod.enforce_auth_required()


def test_non_development_without_keys_refuses_to_start(env):
    """Outside development an unauthenticated security gateway is far more
    likely to be an accident than a choice. Nobody decides the audit trail
    should be world-readable."""
    env.environment, env.api_keys, env.allow_unauthenticated = "production", "", False
    with pytest.raises(RuntimeError) as exc:
        auth_mod.enforce_auth_required()
    assert "SENTINELCORE_ALLOW_UNAUTHENTICATED" in str(exc.value), (
        "refusing to start must name the escape hatch, or it is just an obstacle"
    )


def test_escape_hatch_permits_it_deliberately(env):
    """Legitimate behind a mesh that already authenticates -- but it has to
    be said out loud, because the failure being prevented is nobody having
    considered it."""
    env.environment, env.api_keys, env.allow_unauthenticated = "production", "", True
    auth_mod.enforce_auth_required()


def test_keys_satisfy_the_check_in_any_environment(env):
    env.environment, env.api_keys, env.allow_unauthenticated = "production", "k1:admin", False
    auth_mod.enforce_auth_required()


def test_doctor_reports_the_exposure(capsys, env):
    """`doctor` exists to tell an operator what is wrong before it matters,
    and this is the largest thing it can find."""
    from sentinelcore.cli import _doctor

    env.api_keys = ""
    _doctor(as_json=False)
    assert "UNAUTHENTICATED" in capsys.readouterr().out

    env.api_keys = "k1:admin"
    _doctor(as_json=False)
    assert "authentication configured" in capsys.readouterr().out
