"""
Versioned schema migrations.

The previous approach was `CREATE TABLE IF NOT EXISTS`, which does nothing
to an existing table -- so adding a column required deleting the database.
That is not a migration strategy, and it was documented as an accepted
limitation for pre-release software. It is no longer acceptable for a
package people install.

DESIGN
Migrations are an ordered list of (version, name, [statements]). A
`schema_migrations` table records what has been applied. Startup applies
only what is missing, in order, each inside a transaction.

Two properties matter more than elegance here:

  IDEMPOTENT STARTUP -- running against an already-current database is a
  no-op. Services restart constantly; a migration system that is unsafe to
  re-run is a migration system that eventually destroys data.

  NO SILENT DESTRUCTION -- every migration is additive. There is no DROP or
  destructive ALTER anywhere in this file, and `verify_non_destructive()`
  asserts that, so a future migration that would delete a column fails a
  test rather than a customer's database.

Baseline note: version 1 recreates the pre-migration schema with
`IF NOT EXISTS`, so a database created by an older SentinelCore is adopted
rather than rebuilt. Its rows survive.
"""

import logging
import re

logger = logging.getLogger(__name__)

# (version, name, statements). Append only -- never renumber or edit a
# released migration, because databases in the field have already applied it.
MIGRATIONS: list[tuple[int, str, list[str]]] = [
    (
        1,
        "baseline: adopt pre-migration schema",
        [
            """CREATE TABLE IF NOT EXISTS scan_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                detail TEXT,
                risk_score INTEGER NOT NULL,
                decision TEXT NOT NULL,
                finding_count INTEGER NOT NULL,
                findings_summary TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS approvals (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                arguments_digest TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                status TEXT NOT NULL,
                decided_at TEXT,
                decided_by TEXT,
                reason TEXT
            )""",
            """CREATE TABLE IF NOT EXISTS feedback (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                verdict TEXT NOT NULL,
                note TEXT,
                submitted_by TEXT,
                submitted_at TEXT NOT NULL,
                text_supplied INTEGER NOT NULL DEFAULT 0,
                text TEXT
            )""",
            "CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status)",
            "CREATE INDEX IF NOT EXISTS idx_feedback_verdict ON feedback(verdict)",
            "CREATE INDEX IF NOT EXISTS idx_feedback_scan ON feedback(scan_id)",
        ],
    ),
    (
        2,
        "indexes for retention and dashboard queries",
        [
            # Retention deletes by age; without this it is a full scan on
            # every cleanup, on the largest table in the system.
            "CREATE INDEX IF NOT EXISTS idx_scan_events_timestamp ON scan_events(timestamp)",
            # The dashboard's primary query is 'recent, newest first'.
            "CREATE INDEX IF NOT EXISTS idx_scan_events_id_desc ON scan_events(id DESC)",
            # Decision filtering drives the summary counts.
            "CREATE INDEX IF NOT EXISTS idx_scan_events_decision ON scan_events(decision)",
            "CREATE INDEX IF NOT EXISTS idx_approvals_expires ON approvals(expires_at)",
            "CREATE INDEX IF NOT EXISTS idx_feedback_submitted ON feedback(submitted_at)",
        ],
    ),
]

LATEST_VERSION = max(v for v, _, _ in MIGRATIONS)

_DESTRUCTIVE = re.compile(r"\b(DROP\s+(TABLE|COLUMN|INDEX)|TRUNCATE|DELETE\s+FROM)\b", re.I)


def verify_non_destructive() -> list[str]:
    """Returns any migration statement that would destroy data.

    Enforced by a test rather than by review. A destructive migration is
    the failure mode that cannot be undone in the field, and 'we will
    remember to check' is not a control.
    """
    offenders = []
    for version, name, statements in MIGRATIONS:
        for stmt in statements:
            if _DESTRUCTIVE.search(stmt):
                offenders.append(f"v{version} ({name}): {stmt.strip()[:80]}")
    return offenders


def verify_ordering() -> list[str]:
    """Versions must be unique and ascending; a duplicate or out-of-order
    version silently changes which migrations run."""
    problems = []
    versions = [v for v, _, _ in MIGRATIONS]
    if versions != sorted(versions):
        problems.append("migration versions are not in ascending order")
    if len(set(versions)) != len(versions):
        problems.append("duplicate migration versions")
    if versions and versions[0] != 1:
        problems.append("migrations must start at version 1")
    return problems


def pending(current_version: int) -> list[tuple[int, str, list[str]]]:
    return [m for m in MIGRATIONS if m[0] > current_version]
