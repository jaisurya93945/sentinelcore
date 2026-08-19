"""
Audit logging.

Persists scan/decision METADATA only -- scan_id, timestamp, endpoint,
risk_score, decision, and a findings summary (type/severity/origin/detector).
It never persists raw input/output text, and never persists finding
`evidence` (which can contain matched-text fragments).

This is a deliberate v1 boundary, not an oversight. The tempting
alternative -- store a "redacted" text preview using the same regex
detectors already in this codebase -- would be a false sense of safety:
those detectors have documented gaps (no name/address detection, no
Luhn validation, English-pattern-only prompt injection). Calling
something "redacted" when the redaction itself is known-incomplete is
worse than not storing it at all. See docs/threat-model/README.md.

Uses synchronous sqlite3 with a fresh connection per call -- fine for a
v1 low-throughput baseline, not tuned for real concurrent load (a real
async driver or connection pooling would be needed for that). Logging
failures are always swallowed, never raised: a broken audit log must
never break an actual scan or proxy response.
"""

import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from app.core.config import settings
from app.models.finding import Finding

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    decision TEXT NOT NULL,
    finding_count INTEGER NOT NULL,
    findings_summary TEXT NOT NULL
);
"""


@contextmanager
def _connect():
    conn = sqlite3.connect(settings.audit_db_path)
    try:
        yield conn
    finally:
        conn.close()


def init_db() -> None:
    if not settings.audit_enabled:
        return
    try:
        with _connect() as conn:
            conn.execute(_SCHEMA)
            conn.commit()
    except Exception as e:
        logger.warning(f"Audit DB init failed, audit logging will be a no-op: {e}")


def log_scan_event(scan_id: str, endpoint: str, risk_score: int, decision: str, findings: list[Finding]) -> None:
    if not settings.audit_enabled:
        return
    try:
        summary = [
            {"type": f.type, "severity": f.severity.value, "origin": f.origin, "detector": f.detector}
            for f in findings
        ]
        with _connect() as conn:
            conn.execute(
                "INSERT INTO scan_events "
                "(scan_id, timestamp, endpoint, risk_score, decision, finding_count, findings_summary) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    scan_id,
                    datetime.now(timezone.utc).isoformat(),
                    endpoint,
                    risk_score,
                    decision,
                    len(findings),
                    json.dumps(summary),
                ),
            )
            conn.commit()
    except Exception as e:
        logger.warning(f"Audit log write failed (request was not affected): {e}")


def get_recent_events(limit: int = 50) -> list[dict]:
    if not settings.audit_enabled:
        return []
    try:
        with _connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT scan_id, timestamp, endpoint, risk_score, decision, finding_count, findings_summary "
                "FROM scan_events ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [
                {
                    "scan_id": r["scan_id"],
                    "timestamp": r["timestamp"],
                    "endpoint": r["endpoint"],
                    "risk_score": r["risk_score"],
                    "decision": r["decision"],
                    "finding_count": r["finding_count"],
                    "findings": json.loads(r["findings_summary"]),
                }
                for r in rows
            ]
    except Exception as e:
        logger.warning(f"Audit log read failed: {e}")
        return []
