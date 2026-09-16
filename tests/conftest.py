"""Shared pytest fixtures."""

import pytest

from sentinelcore.core.config import settings
from sentinelcore.storage import reset_store


@pytest.fixture(autouse=True)
def _isolated_storage(tmp_path, monkeypatch):
    """Every test gets a throwaway database.

    `reset_store()` matters: the store is cached process-wide and reads its
    configuration once, which is correct for a server but means a test
    changing the path is otherwise ignored. Reset before AND after, so a
    test that reconfigures the backend cannot leak into the next one.
    """
    monkeypatch.setattr(settings, "audit_db_path", str(tmp_path / "test.db"))
    monkeypatch.setattr(settings, "storage_backend", "sqlite")
    reset_store()
    yield
    reset_store()
