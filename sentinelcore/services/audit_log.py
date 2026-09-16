"""
Audit logging.

Persists decision METADATA only -- scan_id, timestamp, endpoint, an
optional `detail` (a controlled identifier such as a tool name, never
arbitrary user text), risk score, decision, and a findings summary
(type/severity/origin/detector). It never persists raw input or output
text, and never persists finding `evidence`, which can contain
matched-text fragments.

That boundary is deliberate. The tempting alternative -- a "redacted"
preview built from the same regex detectors used elsewhere -- would be a
false guarantee: those detectors have documented gaps (no name/address
detection, no Luhn validation, English-pattern-only). Calling something
redacted when the redaction is known-incomplete is worse than not storing
it. See docs/threat-model/README.md.

STORAGE now lives behind sentinelcore.storage, which supplies migrations,
WAL-mode SQLite, an optional PostgreSQL backend and retention. This module
no longer manages connections or schema.

FAILURE SEMANTICS, unchanged and load-bearing:

    SECURITY DECISION  computed in-process; never depends on storage
    AUDIT PERSISTENCE  may fail; the failure is COUNTED and exposed via
                       GET /api/v1/storage/health
    NOTIFICATION       best-effort, after the durable write

A failed audit write does not mean the decision failed, and does not mean
it succeeded. It means the record is missing -- which is what gets
reported rather than swallowed.
"""

import logging

from sentinelcore.models.finding import Finding
from sentinelcore.storage import QueryFilters, get_store, maybe_run_retention

logger = logging.getLogger(__name__)


def init_db() -> None:
    """Retained for backward compatibility: callers and tests still call it.
    Initialization (including migrations) now happens on first store use."""
    try:
        get_store()
    except Exception as e:
        logger.warning(f"storage initialization failed, audit logging will be a no-op: {e}")


def log_scan_event(scan_id: str, endpoint: str, risk_score: int, decision: str,
                   findings: list[Finding], detail: str | None = None) -> None:
    from sentinelcore.core.config import settings

    if not settings.audit_enabled:
        return
    try:
        summary = [
            {"type": f.type, "severity": f.severity.value, "origin": f.origin, "detector": f.detector}
            for f in findings
        ]
        get_store().write_scan_event(scan_id, endpoint, risk_score, decision, summary, detail)
    except Exception as e:
        logger.warning(f"Audit log write failed (request was not affected): {e}")

    # Opportunistic cleanup, rate-limited internally. Placed after the write
    # so a cleanup failure can never prevent the record being stored.
    try:
        maybe_run_retention()
    except Exception:
        pass

    # Alerting is deliberately last: every decision already flows through
    # this function, so there is one wiring point, and it runs after the
    # durable write and cannot affect it.
    try:
        from sentinelcore.services.alerts import get_manager

        get_manager().notify(scan_id, endpoint, decision, risk_score, findings, detail)
    except Exception as e:
        logger.warning(f"Alert dispatch failed (request and audit unaffected): {e}")


def get_recent_events(limit: int = 50, decision: str | None = None,
                      endpoint: str | None = None, since: str | None = None,
                      offset: int = 0) -> list[dict]:
    """Filtering and paging are new; the default call is unchanged, so
    existing callers keep working."""
    from sentinelcore.core.config import settings

    if not settings.audit_enabled:
        return []
    try:
        return get_store().recent_scan_events(
            QueryFilters(decision=decision, endpoint=endpoint, since=since,
                         limit=limit, offset=offset))
    except Exception as e:
        logger.warning(f"Audit log read failed: {e}")
        return []
