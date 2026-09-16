"""
PostgreSQL integration tests.

ENVIRONMENT-DEPENDENT AND HONESTLY SKIPPED.

These require a real PostgreSQL server. They are skipped unless
SENTINELCORE_TEST_POSTGRES_URL is set, and a skip is reported as a skip --
never as a pass. No PostgreSQL server is reachable from the development
environment in which this backend was written, so the backend is labelled
IMPLEMENTED, NOT INTEGRATION-TESTED in the capability matrix.

Run them with:

    docker run -d --rm -p 5432:5432 -e POSTGRES_PASSWORD=pw --name sc-pg postgres:16
    export SENTINELCORE_TEST_POSTGRES_URL=postgresql://postgres:pw@localhost:5432/postgres
    pytest tests/integration/test_postgres.py -v

They assert PARITY with SQLite rather than merely that Postgres works: the
storage abstraction is only worth having if both backends behave the same.
"""

import os
import threading

import pytest

PG_URL = os.environ.get("SENTINELCORE_TEST_POSTGRES_URL")

pytestmark = pytest.mark.skipif(
    not PG_URL,
    reason="SENTINELCORE_TEST_POSTGRES_URL not set; PostgreSQL integration tests require a live server",
)


@pytest.fixture
def store():
    pytest.importorskip("psycopg_pool", reason="pip install 'sentinelcore[postgres]'")
    from sentinelcore.storage.postgres_backend import PostgresStore

    s = PostgresStore(PG_URL)
    s.initialize()
    # Clean slate without dropping the schema, so a shared test database is
    # not destroyed by running the suite.
    with s._get_pool().connection() as conn:
        with conn.cursor() as cur:
            for t in ("scan_events", "approvals", "feedback"):
                cur.execute(f"DELETE FROM {t}")
        conn.commit()
    yield s
    s.close()


def test_migrations_reach_latest(store):
    from sentinelcore.storage.migrations import LATEST_VERSION

    h = store.health()
    assert h["schema_version"] == LATEST_VERSION and h["up_to_date"]


def test_initialize_is_idempotent(store):
    from sentinelcore.storage.migrations import LATEST_VERSION

    for _ in range(3):
        store.initialize()
    assert store.health()["schema_version"] == LATEST_VERSION


def test_write_and_read_parity(store):
    from sentinelcore.storage.base import QueryFilters

    store.write_scan_event("pg1", "scan", 60, "block",
                           [{"type": "instruction_override", "severity": "high",
                             "origin": "input", "detector": "prompt_injection"}], detail="d")
    rows = store.recent_scan_events(QueryFilters(limit=10))
    assert rows and rows[0]["scan_id"] == "pg1"
    assert rows[0]["findings"][0]["type"] == "instruction_override"


def test_filters_and_paging(store):
    from sentinelcore.storage.base import QueryFilters

    for i in range(10):
        store.write_scan_event(f"p{i}", "scan", 0, "allow" if i % 2 else "block", [])
    assert len(store.recent_scan_events(QueryFilters(decision="block", limit=50))) == 5
    assert len(store.recent_scan_events(QueryFilters(limit=3, offset=3))) == 3


def test_concurrent_writes_are_not_lost(store):
    def writer(tid):
        for i in range(50):
            store.write_scan_event(f"c{tid}-{i}", "scan", 0, "allow", [])

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(4)]
    for t in threads: t.start()
    for t in threads: t.join()
    assert store.count_scan_events() == 200


def test_only_one_concurrent_decider_wins(store):
    store.create_approval("pga", "s", "payment.transfer", "d", 90,
                          "2026-01-01T00:00:00+00:00", "2099-01-01T00:00:00+00:00")
    applied = []

    def decider(v):
        applied.append(store.decide_approval("pga", v, f"u{v}", "", "2026-06-01T00:00:00+00:00")[1])

    threads = [threading.Thread(target=decider, args=(i % 2 == 0,)) for i in range(8)]
    for t in threads: t.start()
    for t in threads: t.join()
    assert sum(applied) == 1


def test_retention_bounds_by_row_count(store):
    from sentinelcore.storage.base import RetentionPolicy

    for i in range(100):
        store.write_scan_event(f"r{i}", "scan", 0, "allow", [])
    store.apply_retention(RetentionPolicy(audit_days=3650, max_audit_rows=20))
    assert store.count_scan_events() == 20


def test_health_redacts_credentials(store):
    h = store.health()
    assert "***" in h["location"] or "@" not in h["location"]
    assert PG_URL.split("@")[0].split(":")[-1] not in str(h), "password leaked into health output"
