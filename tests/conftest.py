"""Shared pytest fixtures."""

import pytest

from app.core.config import settings
from app.services.audit_log import init_db


@pytest.fixture(autouse=True)
def _isolated_audit_db(tmp_path, monkeypatch):
    """Every test gets its own throwaway SQLite file so audit-log tests
    never interfere with each other, and no test run leaves a stray
    database file in the repo."""
    monkeypatch.setattr(settings, "audit_db_path", str(tmp_path / "test_audit.db"))
    init_db()
    yield
