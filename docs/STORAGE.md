# Storage and persistence

## Configuration

```bash
# SQLite — the default, no configuration required
SENTINELCORE_STORAGE_BACKEND=sqlite
SENTINELCORE_AUDIT_DB_PATH=./sentinelcore_audit.db

# PostgreSQL — explicit opt-in
SENTINELCORE_STORAGE_BACKEND=postgres
SENTINELCORE_POSTGRES_URL=postgresql://user:pass@host:5432/db
SENTINELCORE_POSTGRES_POOL_MIN=1
SENTINELCORE_POSTGRES_POOL_MAX=10
```

Backend selection is explicit and never inferred. A misconfigured backend **fails loudly at startup** rather than silently falling back to SQLite — a control plane quietly writing its audit trail somewhere other than where the operator configured it is the worse outcome.

`pip install 'sentinelcore[postgres]'` for the PostgreSQL driver. It is not a base dependency.

## Status

| | Status |
|---|---|
| SQLite backend | **TESTED** — 24 persistence tests incl. concurrency, migration upgrade, retention, failure semantics |
| Migrations | **TESTED** — fresh install, legacy-schema upgrade with row preservation, idempotent restart |
| Retention | **TESTED** — time-based and row-count bounds, policy-scope enforcement, failure isolation |
| PostgreSQL backend | **IMPLEMENTED, NOT INTEGRATION-TESTED** — 8 tests exist and **skip** without a live server; none ran in the development environment |
| High availability | **NOT CLAIMED** — PostgreSQL support is not HA |

## Migrations

Versioned, ordered, additive. `schema_migrations` records what has been applied; startup applies only what is missing, each inside a transaction.

**Version 1 is a baseline that adopts a pre-migration database** using `IF NOT EXISTS`, so an existing SentinelCore installation is upgraded in place and its rows survive. Tested explicitly.

**No migration may be destructive.** `verify_non_destructive()` scans every statement for `DROP`/`TRUNCATE`/`DELETE FROM` and a test asserts it returns empty. A destructive migration is the failure that cannot be undone in the field, and "we will remember to check" is not a control.

## Retention — exactly what is deleted, and when

Two independent bounds:

| Data | Default | Config |
|---|---|---|
| Audit events | 30 days | `SENTINELCORE_RETENTION_AUDIT_DAYS` |
| Feedback | 365 days | `SENTINELCORE_RETENTION_FEEDBACK_DAYS` |
| Approvals | 90 days | `SENTINELCORE_RETENTION_APPROVALS_DAYS` |
| Audit row cap | 1,000,000 | `SENTINELCORE_RETENTION_MAX_AUDIT_ROWS` |

Feedback is kept longest deliberately: operator-reported false positives are the hard negatives the benchmark lacks (Finding 10), so they are training data rather than logs.

**The row cap is a second, independent bound.** Time-based retention alone cannot contain a burst inside the window — the same unbounded-growth class already found and fixed in the rate limiter. When the cap is exceeded the oldest rows are removed by insertion order.

Cleanup runs opportunistically after audit writes, rate-limited to `SENTINELCORE_RETENTION_INTERVAL_SECONDS` (default 3600). There is no scheduler in this package; inventing one for a v1 feature would add a failure mode without adding a guarantee. **With multiple workers, cleanup runs more often than configured** — harmless, since the operation is idempotent. Force a pass with `POST /api/v1/storage/retention/run` (admin).

Nothing outside the configured policy is deleted; a test asserts that a generous policy deletes zero rows.

## Failure semantics

Three things stay distinct, and the distinction is the security property:

```
SECURITY DECISION   computed in-process, NEVER depends on storage
AUDIT PERSISTENCE   may fail; failures are COUNTED and exposed
NOTIFICATION        best-effort, after the durable write
```

| Failure | Behaviour |
|---|---|
| Audit write fails | Request unaffected. `write_failures` and `last_write_error` recorded. **Not treated as a failed decision, and not treated as a successful one — the record is missing, and that is what is reported.** |
| Database unavailable at startup | Gateway serves traffic without durable audit. Logged at ERROR. Retries rate-limited to one per 30s — without backoff an unreachable PostgreSQL costs a connection timeout on *every request*. |
| Migration fails | Transaction rolled back, exception raised. A half-applied schema must stop startup, not be worked around. |
| Corrupt SQLite file | `initialize()` raises. Surfaced rather than silently degrading to no-audit. |
| Retention cleanup fails | Data retained, `retention_failures` incremented, next run retries. A cleanup failure never affects the request that triggered it. |

`GET /api/v1/storage/health` **never raises** — an operator asking "is the audit log working?" must get an answer precisely when it is not. Connection strings are redacted before they appear in any output or log.

## Concurrency

SQLite runs in **WAL** mode with `busy_timeout=5000` and `synchronous=NORMAL`. The previous implementation used the default rollback journal with no busy timeout at all, where readers block writers and a contended lock fails instantly.

Connections are **thread-local** — `sqlite3` objects are not safe to share across threads, and FastAPI runs sync endpoints in a threadpool.

**Why writes stay synchronous on the request path:** measured at **19,603 writes/sec** (0.05ms each) across 8 concurrent threads, with zero lost or duplicated rows. An async queue would trade that for a new failure mode — records lost on crash before flush. A deployment needing more should use PostgreSQL with pooling, not a lossy in-process buffer.

Approval decisions are atomic: a conditional `UPDATE ... WHERE status='pending'`. Verified with 10 concurrent deciders — **exactly one** applies.

## Privacy

Unchanged: no raw input, no raw output, no finding evidence. A test asserts the `scan_events` table has no `text`/`input_text`/`evidence` column and that a critical secret finding leaves no trace of the matched value.
