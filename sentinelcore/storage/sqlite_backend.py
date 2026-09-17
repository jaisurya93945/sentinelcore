"""
SQLite backend. The zero-configuration default.

CONCURRENCY -- the part the previous implementation got wrong
The old code opened a fresh default connection per call. SQLite's default
rollback journal takes a database-wide write lock and readers block
writers, so under concurrent load the gateway hit `database is locked`
with no retry. There was no `busy_timeout` anywhere in the codebase.

This backend sets, on every connection:

  journal_mode=WAL    readers no longer block the writer, and vice versa
  busy_timeout=5000   wait for a contended lock instead of failing instantly
  synchronous=NORMAL  with WAL this is durable across process crash; it
                      risks the last transactions only on OS/power loss,
                      which is the right trade for an audit log that must
                      not slow the request path
  foreign_keys=ON

Connections are THREAD-LOCAL. sqlite3 objects are not safe to share across
threads, and FastAPI runs sync endpoints in a threadpool -- the same
deployment shape that produced the 531/800 corruption fixed earlier.

WHY WRITES ARE STILL SYNCHRONOUS ON THE REQUEST PATH
Measured below in the test suite rather than asserted. WAL-mode inserts
into a local file are sub-millisecond; an async queue would add a failure
mode (records lost on crash before flush) to save time the request does
not notice. If a deployment needs that, Postgres with pooling is the
answer, not a lossy in-process buffer. Stated rather than left implicit.
"""

import json
import logging
import sqlite3
import threading
from pathlib import Path
from typing import Any

from sentinelcore.storage.base import QueryFilters, RetentionPolicy, Store
from sentinelcore.storage.migrations import LATEST_VERSION, pending

logger = logging.getLogger(__name__)


class SQLiteStore(Store):
    def __init__(self, path: str):
        super().__init__()
        self.path = path
        self._local = threading.local()
        self._migration_lock = threading.Lock()

    # -- connection ----------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
            conn.row_factory = sqlite3.Row
            # WAL is persistent once set, but setting it per connection is
            # harmless and makes a fresh file correct immediately.
            for pragma in ("PRAGMA journal_mode=WAL",
                           "PRAGMA busy_timeout=5000",
                           "PRAGMA synchronous=NORMAL",
                           "PRAGMA foreign_keys=ON"):
                try:
                    conn.execute(pragma)
                except sqlite3.Error as e:
                    # :memory: and some filesystems reject WAL. Degrade
                    # rather than refuse to start -- a slower audit log is
                    # better than no gateway.
                    logger.debug(f"pragma {pragma!r} not applied: {e}")
            self._local.conn = conn
        return conn

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    # -- lifecycle -----------------------------------------------------

    def _current_version(self, conn) -> int:
        conn.execute("CREATE TABLE IF NOT EXISTS schema_migrations ("
                     "version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)")
        row = conn.execute("SELECT MAX(version) v FROM schema_migrations").fetchone()
        return row["v"] or 0

    def initialize(self) -> None:
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        # Serialised in-process so concurrent startup threads cannot race;
        # across processes SQLite's own write lock plus the INSERT OR IGNORE
        # on schema_migrations makes a double-apply harmless.
        with self._migration_lock:
            conn = self._conn()
            current = self._current_version(conn)
            todo = pending(current)
            if not todo:
                return
            from datetime import datetime, timezone

            for version, name, statements in todo:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    for stmt in statements:
                        conn.execute(stmt)
                    conn.execute(
                        "INSERT OR IGNORE INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
                        (version, name, datetime.now(timezone.utc).isoformat()),
                    )
                    conn.execute("COMMIT")
                    logger.info(f"applied migration v{version}: {name}")
                except Exception:
                    conn.execute("ROLLBACK")
                    # A half-applied migration is worse than a refused
                    # start: the operator must see this.
                    raise

    def health(self) -> dict[str, Any]:
        try:
            conn = self._conn()
            version = self._current_version(conn)
            journal = conn.execute("PRAGMA journal_mode").fetchone()[0]
            reachable = True
            err = None
        except Exception as e:
            version, journal, reachable, err = -1, None, False, str(e)
        return {
            "backend": "sqlite",
            # Path, not a URL -- nothing credential-bearing to redact here,
            # but the same rule applies: never log a connection string.
            "location": self.path,
            "reachable": reachable,
            "error": err,
            "schema_version": version,
            "latest_schema_version": LATEST_VERSION,
            "up_to_date": version == LATEST_VERSION,
            "journal_mode": journal,
            "stats": self.stats.as_dict(),
        }

    # -- audit ---------------------------------------------------------

    def write_scan_event(self, scan_id, endpoint, risk_score, decision,
                         findings_summary, detail=None) -> bool:
        from datetime import datetime, timezone

        try:
            self._conn().execute(
                "INSERT INTO scan_events (scan_id, timestamp, endpoint, detail, risk_score, "
                "decision, finding_count, findings_summary) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (scan_id, datetime.now(timezone.utc).isoformat(), endpoint, detail,
                 risk_score, decision, len(findings_summary), json.dumps(findings_summary)),
            )
            self.stats.writes += 1
            return True
        except Exception as e:
            self.stats.write_failures += 1
            self.stats.last_write_error = str(e)[:200]
            logger.warning(f"audit write failed (security decision unaffected, record missing): {e}")
            return False

    def recent_scan_events(self, filters: QueryFilters) -> list[dict]:
        sql = ("SELECT scan_id, timestamp, endpoint, detail, risk_score, decision, "
               "finding_count, findings_summary FROM scan_events")
        where, params = [], []
        if filters.decision:
            where.append("decision = ?"); params.append(filters.decision)
        if filters.endpoint:
            where.append("endpoint = ?"); params.append(filters.endpoint)
        if filters.since:
            where.append("timestamp >= ?"); params.append(filters.since)
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params += [filters.limit, filters.offset]
        try:
            rows = self._conn().execute(sql, params).fetchall()
            self.stats.reads += 1
            return [{**dict(r), "findings": json.loads(r["findings_summary"])} for r in rows]
        except Exception as e:
            self.stats.read_failures += 1
            logger.warning(f"audit read failed: {e}")
            return []

    def count_scan_events(self) -> int:
        try:
            return self._conn().execute("SELECT COUNT(*) c FROM scan_events").fetchone()["c"]
        except Exception:
            return -1

    # -- approvals -----------------------------------------------------

    def create_approval(self, approval_id, scan_id, tool_name, arguments_digest,
                        risk_score, created_at, expires_at) -> bool:
        try:
            self._conn().execute(
                "INSERT INTO approvals (id, scan_id, tool_name, arguments_digest, risk_score, "
                "created_at, expires_at, status) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')",
                (approval_id, scan_id, tool_name, arguments_digest, risk_score, created_at, expires_at),
            )
            self.stats.writes += 1
            return True
        except Exception as e:
            self.stats.write_failures += 1
            logger.warning(f"approval create failed: {e}")
            return False

    def _expire(self, conn, now_iso: str) -> None:
        conn.execute("UPDATE approvals SET status='expired' WHERE status='pending' AND expires_at < ?",
                     (now_iso,))

    def get_approval(self, approval_id, now_iso) -> dict | None:
        try:
            conn = self._conn()
            self._expire(conn, now_iso)
            row = conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
            return dict(row) if row else None
        except Exception as e:
            logger.warning(f"approval read failed: {e}")
            return None

    def list_pending_approvals(self, now_iso, limit) -> list[dict]:
        try:
            conn = self._conn()
            self._expire(conn, now_iso)
            rows = conn.execute(
                "SELECT * FROM approvals WHERE status='pending' ORDER BY created_at DESC LIMIT ?",
                (limit,)).fetchall()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.warning(f"approval listing failed: {e}")
            return []

    def decide_approval(self, approval_id, approved, decided_by, reason, now_iso):
        """Atomic transition. The UPDATE is conditional on status='pending',
        so two concurrent deciders cannot both succeed -- the second sees
        rowcount 0 and is told its decision did not apply. Previously this
        was a read-then-write with a window between them."""
        status = "approved" if approved else "denied"
        try:
            conn = self._conn()
            conn.execute("BEGIN IMMEDIATE")
            try:
                self._expire(conn, now_iso)
                cur = conn.execute(
                    "UPDATE approvals SET status=?, decided_at=?, decided_by=?, reason=? "
                    "WHERE id=? AND status='pending'",
                    (status, now_iso, decided_by, reason, approval_id),
                )
                applied = cur.rowcount > 0
                row = conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
            return (dict(row) if row else None), applied
        except Exception as e:
            logger.warning(f"approval decision failed: {e}")
            return None, False

    # -- feedback ------------------------------------------------------

    def write_feedback(self, feedback_id, scan_id, verdict, note, submitted_by, submitted_at) -> bool:
        try:
            self._conn().execute(
                "INSERT INTO feedback (id, scan_id, verdict, note, submitted_by, submitted_at, "
                "text_supplied) VALUES (?, ?, ?, ?, ?, ?, 0)",
                (feedback_id, scan_id, verdict, note, submitted_by, submitted_at),
            )
            self.stats.writes += 1
            return True
        except Exception as e:
            self.stats.write_failures += 1
            logger.warning(f"feedback write failed: {e}")
            return False

    def attach_feedback_text(self, feedback_id, text) -> bool:
        try:
            cur = self._conn().execute(
                "UPDATE feedback SET text = ?, text_supplied = 1 WHERE id = ?", (text, feedback_id))
            return cur.rowcount > 0
        except Exception as e:
            logger.warning(f"feedback text attach failed: {e}")
            return False

    def list_feedback(self, verdict, limit) -> list[dict]:
        try:
            conn = self._conn()
            if verdict:
                rows = conn.execute(
                    "SELECT * FROM feedback WHERE verdict = ? ORDER BY submitted_at DESC LIMIT ?",
                    (verdict, limit)).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM feedback ORDER BY submitted_at DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.warning(f"feedback read failed: {e}")
            return []

    def feedback_counts(self) -> dict[str, int]:
        try:
            rows = self._conn().execute(
                "SELECT verdict, COUNT(*) c FROM feedback GROUP BY verdict").fetchall()
            return {r["verdict"]: r["c"] for r in rows}
        except Exception:
            return {}

    # -- mcp pinning ---------------------------------------------------

    def upsert_mcp_pin(self, pin_id, server, tool_name, fingerprint, definition, now_iso) -> bool:
        try:
            # ON CONFLICT keeps first_seen from the original pin: when the
            # baseline was first established is the interesting fact, and
            # overwriting it would erase how long a tool has been trusted.
            self._conn().execute(
                "INSERT INTO mcp_pins (id, server, tool_name, fingerprint, definition, "
                "first_seen, last_verified, status) VALUES (?,?,?,?,?,?,?,'pinned') "
                "ON CONFLICT(server, tool_name) DO UPDATE SET "
                "fingerprint=excluded.fingerprint, definition=excluded.definition, "
                "last_verified=excluded.last_verified",
                (pin_id, server, tool_name, fingerprint, definition, now_iso, now_iso))
            self.stats.writes += 1
            return True
        except Exception as e:
            self.stats.write_failures += 1
            logger.warning(f"mcp pin write failed: {e}")
            return False

    def list_mcp_pins(self, server=None) -> list[dict]:
        try:
            conn = self._conn()
            if server:
                rows = conn.execute("SELECT * FROM mcp_pins WHERE server = ? ORDER BY tool_name",
                                    (server,)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM mcp_pins ORDER BY server, tool_name").fetchall()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.warning(f"mcp pin read failed: {e}")
            return []

    def record_mcp_change(self, change_id, **ch) -> bool:
        try:
            self._conn().execute(
                "INSERT INTO mcp_changes (id, server, tool_name, change_type, severity, "
                "detected_at, old_fingerprint, new_fingerprint, summary, acknowledged) "
                "VALUES (?,?,?,?,?,?,?,?,?,0)",
                (change_id, ch["server"], ch["tool_name"], ch["change_type"], ch["severity"],
                 ch["detected_at"], ch.get("old_fingerprint"), ch.get("new_fingerprint"),
                 ch["summary"]))
            self.stats.writes += 1
            return True
        except Exception as e:
            self.stats.write_failures += 1
            logger.warning(f"mcp change write failed: {e}")
            return False

    def list_mcp_changes(self, acknowledged=None, limit=100) -> list[dict]:
        try:
            conn = self._conn()
            if acknowledged is None:
                rows = conn.execute("SELECT * FROM mcp_changes ORDER BY detected_at DESC LIMIT ?",
                                    (limit,)).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM mcp_changes WHERE acknowledged = ? ORDER BY detected_at DESC "
                    "LIMIT ?", (1 if acknowledged else 0, limit)).fetchall()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.warning(f"mcp change read failed: {e}")
            return []

    def acknowledge_mcp_change(self, change_id) -> bool:
        try:
            cur = self._conn().execute(
                "UPDATE mcp_changes SET acknowledged = 1 WHERE id = ? AND acknowledged = 0",
                (change_id,))
            return cur.rowcount > 0
        except Exception as e:
            logger.warning(f"mcp change acknowledge failed: {e}")
            return False

    # -- retention -----------------------------------------------------

    def apply_retention(self, policy: RetentionPolicy) -> dict[str, int]:
        from datetime import datetime, timedelta, timezone

        if not policy.enabled:
            return {}
        deleted = {}
        now = datetime.now(timezone.utc)
        try:
            conn = self._conn()
            for table, days, ts_col in (("scan_events", policy.audit_days, "timestamp"),
                                        ("feedback", policy.feedback_days, "submitted_at"),
                                        ("approvals", policy.approvals_days, "created_at")):
                cutoff = (now - timedelta(days=days)).isoformat()
                cur = conn.execute(f"DELETE FROM {table} WHERE {ts_col} < ?", (cutoff,))
                deleted[table] = cur.rowcount

            # Count-based safeguard. Time alone cannot bound a burst inside
            # the retention window -- the same unbounded-growth class fixed
            # in the rate limiter.
            total = self.count_scan_events()
            if policy.max_audit_rows and total > policy.max_audit_rows:
                excess = total - policy.max_audit_rows
                cur = conn.execute(
                    "DELETE FROM scan_events WHERE id IN "
                    "(SELECT id FROM scan_events ORDER BY id ASC LIMIT ?)", (excess,))
                deleted["scan_events_overflow"] = cur.rowcount

            self.stats.retention_runs += 1
            self.stats.rows_deleted += sum(deleted.values())
            return deleted
        except Exception as e:
            self.stats.retention_failures += 1
            # A failed cleanup must not take down the gateway; the table
            # grows until the next run, which the counters make visible.
            logger.warning(f"retention cleanup failed (data retained, will retry): {e}")
            return deleted
