"""Unit tests for API key authentication and role-based authorization."""

import pytest
from fastapi import HTTPException

from app.core.auth import Role, parse_api_keys, require_role
from app.core.config import settings


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
