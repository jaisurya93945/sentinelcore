"""
PostgreSQL backend.

STATUS: IMPLEMENTED, NOT INTEGRATION-TESTED.
No PostgreSQL server is reachable from the development environment, so the
integration tests in tests/integration/test_postgres.py skip unless
SENTINELCORE_TEST_POSTGRES_URL is set. The unit tests that do run cover SQL
generation, configuration parsing and credential redaction. This backend is
NOT claimed to be production validated, and the capability matrix says so.

DIFFERENCES FROM SQLITE THAT ARE EASY TO GET WRONG
  - parameter style is %s, not ?
  - AUTOINCREMENT is BIGSERIAL
  - `INSERT OR IGNORE` is `ON CONFLICT DO NOTHING`
  - a failed statement aborts the whole transaction until rollback, so
    every operation here is explicitly committed or rolled back

CREDENTIALS
The connection URL contains a password. It is never logged, never returned
by health(), and never included in an exception surfaced to a caller --
`_safe_url()` strips userinfo before anything is emitted. A security tool
whose own detectors flag credentials in text must not print its own.

CONNECTION POOLING
psycopg_pool, sized from configuration. A control plane that opens a
connection per request exhausts server-side connections under exactly the
load it is supposed to survive.
"""

import json
import logging
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from sentinelcore.core.identity import current_tenant
from sentinelcore.storage.base import QueryFilters, RetentionPolicy, Store
from sentinelcore.storage.migrations import LATEST_VERSION, pending

logger = logging.getLogger(__name__)

# SQLite DDL translated for PostgreSQL. Kept as an explicit mapping rather
# than generated, because a silent translation bug in schema DDL is
# discovered in production.
_PG_TRANSLATIONS = [
    ("INTEGER PRIMARY KEY AUTOINCREMENT", "BIGSERIAL PRIMARY KEY"),
    ("INSERT OR IGNORE", "INSERT"),
]


def _to_pg_ddl(stmt: str) -> str:
    out = stmt
    for a, b in _PG_TRANSLATIONS:
        out = out.replace(a, b)
    return out


def safe_url(url: str) -> str:
    """Strips userinfo so a connection string can appear in a log or an
    error without leaking the password."""
    try:
        parts = urlsplit(url)
        if parts.hostname is None:
            return "<redacted>"
        netloc = parts.hostname + (f":{parts.port}" if parts.port else "")
        if parts.username:
            netloc = f"{parts.username}:***@{netloc}"
        return urlunsplit((parts.scheme, netloc, parts.path, "", ""))
    except Exception:
        return "<redacted>"


class PostgresStore(Store):
    def __init__(self, url: str, min_size: int = 1, max_size: int = 10):
        super().__init__()
        self.url = url
        self._min_size, self._max_size = min_size, max_size
        self._pool = None

    def _get_pool(self):
        if self._pool is None:
            try:
                from psycopg_pool import ConnectionPool
            except ImportError as e:
                raise RuntimeError(
                    "PostgreSQL backend requires: pip install 'sentinelcore-ai[postgres]'"
                ) from e
            self._pool = ConnectionPool(self.url, min_size=self._min_size,
                                        max_size=self._max_size, open=True)
        return self._pool

    def close(self) -> None:
        if self._pool is not None:
            self._pool.close()
            self._pool = None

    # -- lifecycle -----------------------------------------------------

    def initialize(self) -> None:
        with self._get_pool().connection() as conn:
            with conn.cursor() as cur:
                cur.execute("CREATE TABLE IF NOT EXISTS schema_migrations ("
                            "version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)")
                cur.execute("SELECT MAX(version) FROM schema_migrations")
                current = cur.fetchone()[0] or 0
            conn.commit()

        todo = pending(current)
        if not todo:
            return
        from datetime import datetime, timezone

        for version, name, statements in todo:
            with self._get_pool().connection() as conn:
                try:
                    with conn.cursor() as cur:
                        for stmt in statements:
                            cur.execute(_to_pg_ddl(stmt))
                        cur.execute(
                            "INSERT INTO schema_migrations (version, name, applied_at) "
                            "VALUES (%s, %s, %s) ON CONFLICT (version) DO NOTHING",
                            (version, name, datetime.now(timezone.utc).isoformat()),
                        )
                    conn.commit()
                    logger.info(f"applied migration v{version}: {name}")
                except Exception:
                    conn.rollback()
                    raise

    def health(self) -> dict[str, Any]:
        try:
            with self._get_pool().connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT MAX(version) FROM schema_migrations")
                    version = cur.fetchone()[0] or 0
            reachable, err = True, None
        except Exception as e:
            version, reachable = -1, False
            # The message can embed the connection string; redact it.
            err = safe_url(self.url) + " unreachable"
        return {
            "backend": "postgres",
            "location": safe_url(self.url),
            "reachable": reachable,
            "error": err,
            "schema_version": version,
            "latest_schema_version": LATEST_VERSION,
            "up_to_date": version == LATEST_VERSION,
            "pool": {"min": self._min_size, "max": self._max_size},
            "stats": self.stats.as_dict(),
        }

    # -- helpers -------------------------------------------------------

    def _exec(self, sql: str, params=(), fetch: str | None = None):
        with self._get_pool().connection() as conn:
            try:
                with conn.cursor() as cur:
                    cur.execute(sql, params)
                    result = None
                    if fetch == "one":
                        result = cur.fetchone()
                    elif fetch == "all":
                        result = cur.fetchall()
                    elif fetch == "rowcount":
                        result = cur.rowcount
                    cols = [d[0] for d in cur.description] if cur.description else []
                conn.commit()
                return result, cols
            except Exception:
                conn.rollback()
                raise

    # -- audit ---------------------------------------------------------

    def write_scan_event(self, scan_id, endpoint, risk_score, decision,
                         findings_summary, detail=None) -> bool:
        from datetime import datetime, timezone

        try:
            self._exec(
                "INSERT INTO scan_events (scan_id, timestamp, endpoint, detail, risk_score, "
                "decision, finding_count, findings_summary, tenant) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (scan_id, datetime.now(timezone.utc).isoformat(), endpoint, detail,
                 risk_score, decision, len(findings_summary), json.dumps(findings_summary),
                 current_tenant()))
            self.stats.writes += 1
            return True
        except Exception as e:
            self.stats.write_failures += 1
            self.stats.last_write_error = str(e)[:200]
            logger.warning("audit write failed (security decision unaffected, record missing)")
            return False

    def recent_scan_events(self, filters: QueryFilters) -> list[dict]:
        # Predicate in the LITERAL SQL, not appended at runtime, so the static
        # check in test_tenancy.py can verify it -- same reasoning as the
        # SQLite backend.
        sql = ("SELECT scan_id, timestamp, endpoint, detail, risk_score, decision, "
               "finding_count, findings_summary FROM scan_events WHERE tenant = %s")
        where, params = [], [current_tenant()]
        if filters.decision:
            where.append("decision = %s"); params.append(filters.decision)
        if filters.endpoint:
            where.append("endpoint = %s"); params.append(filters.endpoint)
        if filters.since:
            where.append("timestamp >= %s"); params.append(filters.since)
        if where:
            sql += " AND " + " AND ".join(where)
        sql += " ORDER BY id DESC LIMIT %s OFFSET %s"
        params += [filters.limit, filters.offset]
        try:
            rows, cols = self._exec(sql, params, fetch="all")
            self.stats.reads += 1
            out = []
            for r in rows or []:
                d = dict(zip(cols, r))
                d["findings"] = json.loads(d["findings_summary"])
                out.append(d)
            return out
        except Exception as e:
            self.stats.read_failures += 1
            logger.warning(f"audit read failed: {type(e).__name__}")
            return []

    def count_scan_events(self) -> int:
        try:
            row, _ = self._exec("SELECT COUNT(*) FROM scan_events WHERE tenant = %s",
                                (current_tenant(),), fetch="one")
            return row[0]
        except Exception:
            return -1

    # -- approvals -----------------------------------------------------

    def create_approval(self, approval_id, scan_id, tool_name, arguments_digest,
                        risk_score, created_at, expires_at) -> bool:
        try:
            self._exec("INSERT INTO approvals (id, scan_id, tool_name, arguments_digest, risk_score, "
                       "created_at, expires_at, status, tenant) "
                       "VALUES (%s,%s,%s,%s,%s,%s,%s,'pending',%s)",
                       (approval_id, scan_id, tool_name, arguments_digest, risk_score,
                        created_at, expires_at, current_tenant()))
            self.stats.writes += 1
            return True
        except Exception:
            self.stats.write_failures += 1
            return False

    def get_approval(self, approval_id, now_iso) -> dict | None:
        try:
            self._exec("UPDATE approvals SET status='expired' WHERE status='pending' "
                       "AND expires_at < %s AND tenant = %s", (now_iso, current_tenant()))
            row, cols = self._exec("SELECT * FROM approvals WHERE id = %s AND tenant = %s",
                                   (approval_id, current_tenant()), fetch="one")
            return dict(zip(cols, row)) if row else None
        except Exception:
            return None

    def list_pending_approvals(self, now_iso, limit) -> list[dict]:
        try:
            self._exec("UPDATE approvals SET status='expired' WHERE status='pending' "
                       "AND expires_at < %s AND tenant = %s", (now_iso, current_tenant()))
            rows, cols = self._exec("SELECT * FROM approvals WHERE status='pending' "
                                    "AND tenant = %s ORDER BY created_at DESC LIMIT %s",
                                    (current_tenant(), limit), fetch="all")
            return [dict(zip(cols, r)) for r in rows or []]
        except Exception:
            return []

    def decide_approval(self, approval_id, approved, decided_by, reason, now_iso):
        status = "approved" if approved else "denied"
        try:
            with self._get_pool().connection() as conn:
                try:
                    with conn.cursor() as cur:
                        cur.execute("UPDATE approvals SET status='expired' WHERE status='pending' "
                                    "AND expires_at < %s AND tenant = %s",
                                    (now_iso, current_tenant()))
                        cur.execute("UPDATE approvals SET status=%s, decided_at=%s, decided_by=%s, "
                                    "reason=%s WHERE id=%s AND status='pending' AND tenant=%s",
                                    (status, now_iso, decided_by, reason, approval_id,
                                     current_tenant()))
                        applied = cur.rowcount > 0
                        cur.execute("SELECT * FROM approvals WHERE id = %s AND tenant = %s",
                                    (approval_id, current_tenant()))
                        row = cur.fetchone()
                        cols = [d[0] for d in cur.description]
                    conn.commit()
                    return (dict(zip(cols, row)) if row else None), applied
                except Exception:
                    conn.rollback()
                    raise
        except Exception:
            return None, False

    # -- feedback ------------------------------------------------------

    def write_feedback(self, feedback_id, scan_id, verdict, note, submitted_by, submitted_at) -> bool:
        try:
            self._exec("INSERT INTO feedback (id, scan_id, verdict, note, submitted_by, "
                       "submitted_at, text_supplied, tenant) VALUES (%s,%s,%s,%s,%s,%s,0,%s)",
                       (feedback_id, scan_id, verdict, note, submitted_by, submitted_at,
                        current_tenant()))
            self.stats.writes += 1
            return True
        except Exception:
            self.stats.write_failures += 1
            return False

    def attach_feedback_text(self, feedback_id, text) -> bool:
        try:
            rc, _ = self._exec("UPDATE feedback SET text=%s, text_supplied=1 "
                               "WHERE id=%s AND tenant=%s",
                               (text, feedback_id, current_tenant()), fetch="rowcount")
            return bool(rc)
        except Exception:
            return False

    def list_feedback(self, verdict, limit) -> list[dict]:
        try:
            if verdict:
                rows, cols = self._exec("SELECT * FROM feedback WHERE verdict=%s AND tenant=%s "
                                        "ORDER BY submitted_at DESC LIMIT %s",
                                        (verdict, current_tenant(), limit), fetch="all")
            else:
                rows, cols = self._exec("SELECT * FROM feedback WHERE tenant=%s "
                                        "ORDER BY submitted_at DESC LIMIT %s",
                                        (current_tenant(), limit), fetch="all")
            return [dict(zip(cols, r)) for r in rows or []]
        except Exception:
            return []

    def feedback_counts(self) -> dict[str, int]:
        try:
            rows, _ = self._exec("SELECT verdict, COUNT(*) FROM feedback WHERE tenant=%s "
                                 "GROUP BY verdict", (current_tenant(),), fetch="all")
            return {r[0]: r[1] for r in rows or []}
        except Exception:
            return {}

    # -- mcp pinning ---------------------------------------------------

    def upsert_mcp_pin(self, pin_id, server, tool_name, fingerprint, definition, now_iso) -> bool:
        try:
            self._exec(
                "INSERT INTO mcp_pins (id, server, tool_name, fingerprint, definition, "
                "first_seen, last_verified, status, tenant) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,'pinned',%s) "
                "ON CONFLICT (tenant, server, tool_name) DO UPDATE SET "
                "fingerprint=EXCLUDED.fingerprint, definition=EXCLUDED.definition, "
                "last_verified=EXCLUDED.last_verified",
                (pin_id, server, tool_name, fingerprint, definition, now_iso, now_iso,
                 current_tenant()))
            self.stats.writes += 1
            return True
        except Exception:
            self.stats.write_failures += 1
            return False

    def list_mcp_pins(self, server=None) -> list[dict]:
        try:
            if server:
                rows, cols = self._exec("SELECT * FROM mcp_pins WHERE server=%s AND tenant=%s "
                                        "ORDER BY tool_name", (server, current_tenant()),
                                        fetch="all")
            else:
                rows, cols = self._exec("SELECT * FROM mcp_pins WHERE tenant=%s "
                                        "ORDER BY server, tool_name", (current_tenant(),),
                                        fetch="all")
            return [dict(zip(cols, r)) for r in rows or []]
        except Exception:
            return []

    def record_mcp_change(self, change_id, **ch) -> bool:
        try:
            self._exec(
                "INSERT INTO mcp_changes (id, server, tool_name, change_type, severity, "
                "detected_at, old_fingerprint, new_fingerprint, summary, acknowledged, tenant) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,0,%s)",
                (change_id, ch["server"], ch["tool_name"], ch["change_type"], ch["severity"],
                 ch["detected_at"], ch.get("old_fingerprint"), ch.get("new_fingerprint"),
                 ch["summary"], current_tenant()))
            self.stats.writes += 1
            return True
        except Exception:
            self.stats.write_failures += 1
            return False

    def list_mcp_changes(self, acknowledged=None, limit=100) -> list[dict]:
        try:
            if acknowledged is None:
                rows, cols = self._exec("SELECT * FROM mcp_changes WHERE tenant=%s "
                                        "ORDER BY detected_at DESC LIMIT %s",
                                        (current_tenant(), limit), fetch="all")
            else:
                rows, cols = self._exec("SELECT * FROM mcp_changes WHERE acknowledged=%s "
                                        "AND tenant=%s ORDER BY detected_at DESC LIMIT %s",
                                        (1 if acknowledged else 0, current_tenant(), limit),
                                        fetch="all")
            return [dict(zip(cols, r)) for r in rows or []]
        except Exception:
            return []

    def acknowledge_mcp_change(self, change_id) -> bool:
        try:
            rc, _ = self._exec("UPDATE mcp_changes SET acknowledged=1 WHERE id=%s AND "
                               "acknowledged=0 AND tenant=%s",
                               (change_id, current_tenant()), fetch="rowcount")
            return bool(rc)
        except Exception:
            return False

    # -- retention -----------------------------------------------------

    def apply_retention(self, policy: RetentionPolicy) -> dict[str, int]:
        from datetime import datetime, timedelta, timezone

        if not policy.enabled:
            return {}
        deleted, now = {}, datetime.now(timezone.utc)
        try:
            for table, days, col in (("scan_events", policy.audit_days, "timestamp"),
                                     ("feedback", policy.feedback_days, "submitted_at"),
                                     ("approvals", policy.approvals_days, "created_at")):
                cutoff = (now - timedelta(days=days)).isoformat()
                rc, _ = self._exec(f"DELETE FROM {table} WHERE {col} < %s AND tenant = %s",
                                   (cutoff, current_tenant()), fetch="rowcount")
                deleted[table] = rc or 0
            total = self.count_scan_events()
            if policy.max_audit_rows and total > policy.max_audit_rows:
                rc, _ = self._exec(
                    "DELETE FROM scan_events WHERE id IN "
                    "(SELECT id FROM scan_events WHERE tenant = %s ORDER BY id ASC LIMIT %s)",
                    (current_tenant(), total - policy.max_audit_rows), fetch="rowcount")
                deleted["scan_events_overflow"] = rc or 0
            self.stats.retention_runs += 1
            self.stats.rows_deleted += sum(deleted.values())
            return deleted
        except Exception as e:
            self.stats.retention_failures += 1
            logger.warning(f"retention cleanup failed (data retained, will retry): {type(e).__name__}")
            return deleted
