"""
Storage factory and process-wide store.

Backend selection is explicit configuration, never inferred. SQLite stays
the default so `pip install sentinelcore` works with no database to set up.

    SENTINELCORE_STORAGE_BACKEND=sqlite            (default)
    SENTINELCORE_AUDIT_DB_PATH=./sentinelcore.db

    SENTINELCORE_STORAGE_BACKEND=postgres
    SENTINELCORE_POSTGRES_URL=postgresql://user:pass@host/db

Retention runs opportunistically after writes rather than on a scheduler:
this package has no scheduler, and inventing one to support a v1 feature
would add a failure mode without adding a guarantee. The interval is
checked in-process, so a deployment with several workers runs cleanup more
often than configured -- harmless, since the operation is idempotent, and
stated rather than left to be discovered.
"""

import logging
import threading
import time

from sentinelcore.core.config import settings
from sentinelcore.storage.base import QueryFilters, RetentionPolicy, StorageStats, Store

logger = logging.getLogger(__name__)

__all__ = ["Store", "QueryFilters", "RetentionPolicy", "StorageStats", "StorageUnavailable",
           "get_store", "reset_store", "maybe_run_retention", "storage_health"]

_store: Store | None = None
_lock = threading.Lock()
_last_retention = 0.0

# Backoff after a failed initialization. Without it every request retries
# the connection: harmless for a local SQLite file (measured at 0.2ms) but
# severe for an unreachable PostgreSQL, where each attempt pays a network
# timeout on the request path and floods the log. The gateway keeps serving
# either way -- storage failure must not change a security decision -- but
# it should not pay for the same failure on every request.
_init_failed_at = 0.0
_init_error: str | None = None
INIT_RETRY_SECONDS = 30.0


def _build() -> Store:
    backend = (settings.storage_backend or "sqlite").strip().lower()
    if backend == "sqlite":
        from sentinelcore.storage.sqlite_backend import SQLiteStore

        return SQLiteStore(settings.audit_db_path)
    if backend in ("postgres", "postgresql"):
        if not settings.postgres_url:
            raise ValueError(
                "SENTINELCORE_STORAGE_BACKEND=postgres requires SENTINELCORE_POSTGRES_URL"
            )
        from sentinelcore.storage.postgres_backend import PostgresStore

        return PostgresStore(settings.postgres_url,
                             min_size=settings.postgres_pool_min,
                             max_size=settings.postgres_pool_max)
    raise ValueError(f"unknown storage backend {backend!r}; expected 'sqlite' or 'postgres'")


class StorageUnavailable(RuntimeError):
    """Raised when the store could not be initialized. Callers on the
    request path catch this and continue -- a missing audit record is
    reported, never treated as a failed security decision."""


def get_store() -> Store:
    """Process-wide store, created on first use and initialized once.

    After an initialization failure, retries are rate-limited to one per
    INIT_RETRY_SECONDS so an unreachable database costs one timeout per
    interval rather than one per request.
    """
    global _store, _init_failed_at, _init_error
    if _store is not None:
        return _store
    with _lock:
        if _store is not None:
            return _store
        if _init_failed_at and (time.monotonic() - _init_failed_at) < INIT_RETRY_SECONDS:
            raise StorageUnavailable(f"storage unavailable (retrying in "
                                     f"{INIT_RETRY_SECONDS - (time.monotonic() - _init_failed_at):.0f}s): "
                                     f"{_init_error}")
        try:
            store = _build()
            store.initialize()
        except Exception as e:
            _init_failed_at = time.monotonic()
            # str(e) can embed a connection string for Postgres; the
            # backend redacts in health(), and we keep only the type here.
            _init_error = type(e).__name__
            logger.error(f"storage initialization failed ({_init_error}); "
                         f"the gateway continues WITHOUT durable audit until it recovers")
            raise StorageUnavailable(_init_error) from e
        _store = store
        _init_failed_at, _init_error = 0.0, None
    return _store


def storage_health() -> dict:
    """Never raises. An operator asking 'is the audit log working?' must get
    an answer even when it is not."""
    global _init_failed_at, _init_error
    try:
        return get_store().health()
    except Exception as e:
        return {
            "backend": settings.storage_backend,
            "reachable": False,
            "error": type(e).__name__ if not _init_error else _init_error,
            "retrying_in_seconds": max(0, round(INIT_RETRY_SECONDS - (time.monotonic() - _init_failed_at)))
                                   if _init_failed_at else 0,
            "up_to_date": False,
            "note": "security decisions are unaffected; audit records are NOT being persisted",
        }


def reset_store() -> None:
    """Drops the cached store. Used by tests and by configuration reloads;
    closing is best-effort because a store that failed to open may not be
    closable."""
    global _store, _last_retention, _init_failed_at, _init_error
    with _lock:
        if _store is not None:
            try:
                _store.close()
            except Exception:
                pass
        _store = None
        _last_retention = 0.0
        _init_failed_at = 0.0
        _init_error = None


def current_policy() -> RetentionPolicy:
    return RetentionPolicy(
        audit_days=settings.retention_audit_days,
        feedback_days=settings.retention_feedback_days,
        approvals_days=settings.retention_approvals_days,
        max_audit_rows=settings.retention_max_audit_rows,
        enabled=settings.retention_enabled,
    )


def maybe_run_retention(force: bool = False) -> dict[str, int] | None:
    """Runs cleanup if the interval has elapsed. Never raises: a failed
    cleanup must not affect the request that happened to trigger it."""
    global _last_retention
    if not settings.retention_enabled and not force:
        return None
    now = time.monotonic()
    if not force and (now - _last_retention) < settings.retention_interval_seconds:
        return None
    with _lock:
        if not force and (now - _last_retention) < settings.retention_interval_seconds:
            return None
        _last_retention = now
    try:
        return get_store().apply_retention(current_policy())
    except Exception as e:
        logger.warning(f"retention run failed: {type(e).__name__}")
        return None
