"""
Persistence tests.

Covers the properties P1-8 exists to guarantee: migrations that upgrade
rather than recreate, concurrency that does not lose or duplicate writes,
retention that bounds growth without deleting outside policy, and failure
behaviour that is visible rather than silent.
"""

import os
import sqlite3
import threading

import pytest

from sentinelcore.core.config import settings
from sentinelcore.storage import (QueryFilters, RetentionPolicy, StorageUnavailable,
                                  get_store, maybe_run_retention, reset_store, storage_health)
from sentinelcore.storage.migrations import (LATEST_VERSION, MIGRATIONS, pending,
                                             verify_non_destructive, verify_ordering)
from sentinelcore.storage.sqlite_backend import SQLiteStore


# --- migrations ---------------------------------------------------------

def test_no_migration_is_destructive():
    """Enforced rather than reviewed: a destructive migration is the failure
    that cannot be undone in the field."""
    assert verify_non_destructive() == []


def test_migration_versions_are_ordered_and_unique():
    assert verify_ordering() == []


def test_fresh_database_reaches_the_latest_schema(tmp_path):
    s = SQLiteStore(str(tmp_path / "fresh.db"))
    s.initialize()
    h = s.health()
    assert h["schema_version"] == LATEST_VERSION and h["up_to_date"]


def test_initialize_is_idempotent(tmp_path):
    """Services restart constantly; a migration system unsafe to re-run
    eventually destroys data."""
    path = str(tmp_path / "idem.db")
    s = SQLiteStore(path)
    for _ in range(5):
        s.initialize()
    assert s.health()["schema_version"] == LATEST_VERSION
    assert pending(s.health()["schema_version"]) == []


def test_upgrade_from_pre_migration_schema_preserves_rows(tmp_path):
    """The real upgrade path: a database created by an older SentinelCore,
    with no schema_migrations table and existing data, must be ADOPTED --
    not recreated."""
    path = str(tmp_path / "legacy.db")
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE scan_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL,
            timestamp TEXT NOT NULL, endpoint TEXT NOT NULL, detail TEXT,
            risk_score INTEGER NOT NULL, decision TEXT NOT NULL,
            finding_count INTEGER NOT NULL, findings_summary TEXT NOT NULL);
        CREATE TABLE approvals (
            id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, tool_name TEXT NOT NULL,
            arguments_digest TEXT NOT NULL, risk_score INTEGER NOT NULL,
            created_at TEXT NOT NULL, expires_at TEXT NOT NULL, status TEXT NOT NULL,
            decided_at TEXT, decided_by TEXT, reason TEXT);
        CREATE TABLE feedback (
            id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, verdict TEXT NOT NULL,
            note TEXT, submitted_by TEXT, submitted_at TEXT NOT NULL,
            text_supplied INTEGER NOT NULL DEFAULT 0, text TEXT);
    """)
    conn.execute("INSERT INTO scan_events (scan_id,timestamp,endpoint,risk_score,decision,"
                 "finding_count,findings_summary) VALUES ('legacy','2026-01-01T00:00:00Z','scan',60,"
                 "'block',1,'[]')")
    conn.commit(); conn.close()

    s = SQLiteStore(path)
    s.initialize()
    assert s.health()["schema_version"] == LATEST_VERSION
    rows = s.recent_scan_events(QueryFilters(limit=10))
    assert any(r["scan_id"] == "legacy" for r in rows), "pre-existing rows were lost on upgrade"


def test_migration_applied_twice_does_not_duplicate_history(tmp_path):
    s = SQLiteStore(str(tmp_path / "hist.db"))
    s.initialize(); s.initialize()
    rows = s._conn().execute("SELECT version, COUNT(*) c FROM schema_migrations GROUP BY version").fetchall()
    assert all(r["c"] == 1 for r in rows)


# --- concurrency --------------------------------------------------------

def test_concurrent_writes_are_neither_lost_nor_duplicated(tmp_path):
    s = SQLiteStore(str(tmp_path / "conc.db")); s.initialize()

    def writer(tid):
        for i in range(100):
            s.write_scan_event(f"t{tid}-{i}", "scan", 10, "allow", [])

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(6)]
    for t in threads: t.start()
    for t in threads: t.join()
    assert s.count_scan_events() == 600
    assert s.stats.write_failures == 0


def test_readers_do_not_fail_during_sustained_writes(tmp_path):
    """The WAL claim. Under the old default journal this raised
    'database is locked' with no busy_timeout anywhere in the codebase."""
    s = SQLiteStore(str(tmp_path / "wal.db")); s.initialize()
    errors, stop = [], threading.Event()

    def reader():
        while not stop.is_set():
            try:
                s.recent_scan_events(QueryFilters(limit=10))
            except Exception as e:
                errors.append(e)

    readers = [threading.Thread(target=reader) for _ in range(3)]
    for r in readers: r.start()
    for i in range(300):
        s.write_scan_event(f"w{i}", "scan", 0, "allow", [])
    stop.set()
    for r in readers: r.join()
    assert not errors, f"readers blocked by writer: {errors[:1]}"


def test_wal_is_enabled(tmp_path):
    s = SQLiteStore(str(tmp_path / "j.db")); s.initialize()
    assert s.health()["journal_mode"].lower() == "wal"


def test_only_one_concurrent_decider_can_win(tmp_path):
    """Previously a read-then-write with a window between them."""
    s = SQLiteStore(str(tmp_path / "appr.db")); s.initialize()
    s.create_approval("a1", "s", "payment.transfer", "d", 90,
                      "2026-01-01T00:00:00+00:00", "2099-01-01T00:00:00+00:00")
    applied = []

    def decider(v):
        applied.append(s.decide_approval("a1", v, f"u{v}", "", "2026-06-01T00:00:00+00:00")[1])

    threads = [threading.Thread(target=decider, args=(i % 2 == 0,)) for i in range(10)]
    for t in threads: t.start()
    for t in threads: t.join()
    assert sum(applied) == 1, f"{sum(applied)} deciders succeeded; must be exactly one"


# --- restart / recovery -------------------------------------------------

def test_data_survives_reopen(tmp_path):
    path = str(tmp_path / "persist.db")
    s = SQLiteStore(path); s.initialize()
    s.write_scan_event("keep-me", "scan", 60, "block", [])
    s.close()
    s2 = SQLiteStore(path); s2.initialize()
    assert any(r["scan_id"] == "keep-me" for r in s2.recent_scan_events(QueryFilters(limit=10)))


# --- retention ----------------------------------------------------------

def test_retention_bounds_growth_by_row_count(tmp_path):
    """Time-based retention alone cannot contain a burst inside the window
    -- the same unbounded-growth class fixed in the rate limiter."""
    s = SQLiteStore(str(tmp_path / "ret.db")); s.initialize()
    for i in range(500):
        s.write_scan_event(f"r{i}", "scan", 0, "allow", [])
    s.apply_retention(RetentionPolicy(audit_days=3650, max_audit_rows=100))
    assert s.count_scan_events() == 100


def test_retention_deletes_only_what_the_policy_specifies(tmp_path):
    s = SQLiteStore(str(tmp_path / "ret2.db")); s.initialize()
    for i in range(10):
        s.write_scan_event(f"n{i}", "scan", 0, "allow", [])
    s.write_feedback("f1", "s", "false_positive", "", "", "2026-06-01T00:00:00+00:00")
    # Generous windows: nothing is old enough, and the row cap is not hit.
    deleted = s.apply_retention(RetentionPolicy(audit_days=3650, feedback_days=3650,
                                                approvals_days=3650, max_audit_rows=10_000))
    assert sum(deleted.values()) == 0, f"deleted data outside the policy: {deleted}"
    assert s.count_scan_events() == 10
    assert len(s.list_feedback(None, 10)) == 1


def test_retention_disabled_deletes_nothing(tmp_path):
    s = SQLiteStore(str(tmp_path / "ret3.db")); s.initialize()
    for i in range(5):
        s.write_scan_event(f"x{i}", "scan", 0, "allow", [])
    assert s.apply_retention(RetentionPolicy(enabled=False)) == {}
    assert s.count_scan_events() == 5


def test_retention_failure_is_counted_not_raised(tmp_path, monkeypatch):
    s = SQLiteStore(str(tmp_path / "ret4.db")); s.initialize()
    monkeypatch.setattr(s, "count_scan_events", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    s.apply_retention(RetentionPolicy(max_audit_rows=1))   # must not raise
    assert s.stats.retention_failures >= 1


# --- failure semantics --------------------------------------------------

def test_write_failure_is_counted_and_reported(tmp_path, monkeypatch):
    """A failed audit write must not be silent. These counters are how an
    operator discovers the audit log has been unwritable."""
    s = SQLiteStore(str(tmp_path / "fail.db")); s.initialize()
    monkeypatch.setattr(s, "_conn", lambda: (_ for _ in ()).throw(sqlite3.OperationalError("disk full")))
    assert s.write_scan_event("s", "scan", 0, "allow", []) is False
    assert s.stats.write_failures == 1
    assert "disk full" in (s.stats.last_write_error or "")


def test_corrupt_database_surfaces_rather_than_silently_losing_audit(tmp_path):
    path = tmp_path / "corrupt.db"
    path.write_bytes(b"definitely not sqlite" * 100)
    s = SQLiteStore(str(path))
    with pytest.raises(Exception):
        s.initialize()


def test_storage_health_never_raises_when_storage_is_broken(tmp_path, monkeypatch):
    """An operator asking 'is the audit log working?' must get an answer
    precisely when it is not."""
    bad = tmp_path / "bad.db"
    bad.write_bytes(b"nope" * 200)
    monkeypatch.setattr(settings, "audit_db_path", str(bad))
    reset_store()
    h = storage_health()
    assert h["reachable"] is False
    assert "NOT being persisted" in h["note"]
    reset_store()


def test_failed_initialization_backs_off(tmp_path, monkeypatch):
    """Without backoff an unreachable database costs a connection timeout
    on every request."""
    bad = tmp_path / "bad2.db"
    bad.write_bytes(b"nope" * 200)
    monkeypatch.setattr(settings, "audit_db_path", str(bad))
    reset_store()
    with pytest.raises(StorageUnavailable):
        get_store()
    with pytest.raises(StorageUnavailable) as e:
        get_store()
    assert "retrying in" in str(e.value)
    reset_store()


# --- configuration ------------------------------------------------------

def test_unknown_backend_is_rejected(monkeypatch):
    monkeypatch.setattr(settings, "storage_backend", "mysql")
    reset_store()
    with pytest.raises(Exception):
        get_store()
    reset_store()


def test_postgres_without_url_is_rejected(monkeypatch):
    monkeypatch.setattr(settings, "storage_backend", "postgres")
    monkeypatch.setattr(settings, "postgres_url", "")
    reset_store()
    with pytest.raises(Exception):
        get_store()
    reset_store()


def test_sqlite_remains_the_default():
    assert settings.storage_backend == "sqlite"


# --- privacy ------------------------------------------------------------

def test_no_raw_text_or_evidence_is_persisted(tmp_path):
    """The persistence layer must not become an accidental content store."""
    s = SQLiteStore(str(tmp_path / "priv.db")); s.initialize()
    s.write_scan_event("s", "scan", 90, "block",
                       [{"type": "aws_access_key", "severity": "critical",
                         "origin": "input", "detector": "secrets"}])
    row = s._conn().execute("SELECT * FROM scan_events").fetchone()
    blob = " ".join(str(v) for v in dict(row).values())
    assert "AKIA" not in blob and "evidence" not in blob
    cols = {d[0] for d in s._conn().execute("SELECT * FROM scan_events LIMIT 1").description}
    assert "text" not in cols and "input_text" not in cols and "evidence" not in cols


def test_postgres_url_credentials_are_redacted():
    from sentinelcore.storage.postgres_backend import safe_url

    assert "hunter2" not in safe_url("postgresql://admin:hunter2@db.internal:5432/prod")
    assert "db.internal" in safe_url("postgresql://admin:hunter2@db.internal:5432/prod")
    assert safe_url("garbage") == "<redacted>"
