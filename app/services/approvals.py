"""
Human approval workflow.

Until now HUMAN_APPROVAL was a decision the policy engine could return
with nothing behind it: the tool-call endpoint reported it and the caller
was left to invent a mechanism. That is the same defect SANITIZE had --
a recommendation presented as though an action had occurred -- and it is
worse here, because HUMAN_APPROVAL is reserved for the highest-
consequence actions in the system (payment.transfer, and anything an
operator marks as requiring a person in the loop).

WHAT THIS ADDS
A real approval record with a lifecycle:

    PENDING --> APPROVED   (a human explicitly allowed it)
            --> DENIED     (a human explicitly refused it)
            --> EXPIRED    (nobody answered within the TTL)

FAIL-CLOSED ON EXPIRY, DELIBERATELY
An approval nobody answers becomes EXPIRED, and EXPIRED is treated as a
refusal, not as consent. This is the single most important decision in
this module. The alternative -- letting an unanswered request time out
into approval -- would convert an operator being asleep into
authorisation for a privileged action, which is precisely the failure
mode a human-in-the-loop control exists to prevent. It also means a
denial-of-service against the approval channel degrades to "nothing
executes" rather than "everything executes".

WHAT THIS IS NOT
There is no notification delivery here -- no email, no Slack, no pager.
The record is created and queryable; getting a human's attention is an
integration concern and pretending otherwise would be theatre. There is
also no authentication of WHO approved beyond a caller-supplied
identifier, because this project has no identity system to bind it to;
`decided_by` is recorded as an unverified string and is labelled as such.
"""

import logging
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from enum import Enum

from app.core.config import settings

logger = logging.getLogger(__name__)


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


# Statuses that permit the action to proceed. Exactly one, on purpose.
PERMITS_EXECUTION = {ApprovalStatus.APPROVED}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS approvals (
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
);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status);
"""


@contextmanager
def _connect():
    conn = sqlite3.connect(settings.audit_db_path)
    try:
        conn.row_factory = sqlite3.Row
        yield conn
    finally:
        conn.close()


def init_db() -> None:
    try:
        with _connect() as conn:
            conn.executescript(_SCHEMA)
            conn.commit()
    except Exception as e:
        logger.warning(f"Approval store init failed: {e}")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _expire_stale(conn) -> None:
    """Lazily expires overdue records on read. Deliberately not a
    background job: this system has no scheduler, and inventing one to
    support a v1 feature would add a failure mode without adding a
    guarantee. The cost is that `expires_at` is authoritative and status
    only catches up when someone looks -- which is safe precisely because
    EXPIRED and PENDING are both non-permitting."""
    conn.execute(
        "UPDATE approvals SET status = ? WHERE status = ? AND expires_at < ?",
        (ApprovalStatus.EXPIRED.value, ApprovalStatus.PENDING.value, _now().isoformat()),
    )


def request_approval(scan_id: str, tool_name: str, arguments_digest: str, risk_score: int) -> str | None:
    """Creates a PENDING approval and returns its id, or None if the store
    is unavailable. Returning None must be treated by the caller as
    'not approved' -- see the fail-closed note in the module docstring."""
    approval_id = str(uuid.uuid4())
    now = _now()
    try:
        with _connect() as conn:
            conn.execute(
                "INSERT INTO approvals (id, scan_id, tool_name, arguments_digest, risk_score, "
                "created_at, expires_at, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (approval_id, scan_id, tool_name, arguments_digest, risk_score,
                 now.isoformat(),
                 (now + timedelta(seconds=settings.approval_ttl_seconds)).isoformat(),
                 ApprovalStatus.PENDING.value),
            )
            conn.commit()
        return approval_id
    except Exception as e:
        logger.warning(f"Could not record approval request: {e}")
        return None


def get_approval(approval_id: str) -> dict | None:
    try:
        with _connect() as conn:
            _expire_stale(conn)
            conn.commit()
            row = conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
            return dict(row) if row else None
    except Exception as e:
        logger.warning(f"Approval lookup failed: {e}")
        return None


def list_pending(limit: int = 50) -> list[dict]:
    try:
        with _connect() as conn:
            _expire_stale(conn)
            conn.commit()
            rows = conn.execute(
                "SELECT * FROM approvals WHERE status = ? ORDER BY created_at DESC LIMIT ?",
                (ApprovalStatus.PENDING.value, limit),
            ).fetchall()
            return [dict(r) for r in rows]
    except Exception as e:
        logger.warning(f"Pending approval listing failed: {e}")
        return []


def decide(approval_id: str, approved: bool, decided_by: str, reason: str = "") -> tuple[dict | None, bool]:
    """Records a human decision.

    Returns (record, applied). `applied` is False when the record was
    already terminal -- expired, or previously decided. The caller MUST
    distinguish these: silently returning success for a decision that did
    not take effect would let an operator believe they had denied
    something that is in fact approved, which is a worse failure than an
    error. Only a PENDING approval can be decided; a late approval must
    not revive an action whose context has gone stale."""
    try:
        with _connect() as conn:
            _expire_stale(conn)
            row = conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
            if row is None:
                conn.commit()
                return None, False
            if row["status"] != ApprovalStatus.PENDING.value:
                conn.commit()
                return dict(row), False  # already terminal -- decision NOT applied

            status = ApprovalStatus.APPROVED if approved else ApprovalStatus.DENIED
            conn.execute(
                "UPDATE approvals SET status = ?, decided_at = ?, decided_by = ?, reason = ? WHERE id = ?",
                (status.value, _now().isoformat(), decided_by, reason, approval_id),
            )
            conn.commit()
            return dict(conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()), True
    except Exception as e:
        logger.warning(f"Approval decision failed: {e}")
        return None, False


def permits_execution(approval_id: str) -> bool:
    """The single question the enforcement path asks. Anything other than
    an explicit APPROVED -- pending, denied, expired, missing, or a store
    error -- returns False."""
    record = get_approval(approval_id)
    if record is None:
        return False
    return record["status"] in {s.value for s in PERMITS_EXECUTION}
