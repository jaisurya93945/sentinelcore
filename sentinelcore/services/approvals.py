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
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum

from sentinelcore.core.config import settings
from sentinelcore.storage import get_store

logger = logging.getLogger(__name__)


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


# Statuses that permit the action to proceed. Exactly one, on purpose.
PERMITS_EXECUTION = {ApprovalStatus.APPROVED}


def init_db() -> None:
    """Kept for backward compatibility; schema now comes from migrations."""
    try:
        get_store()
    except Exception as e:
        logger.warning(f"Approval store init failed: {e}")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def request_approval(scan_id: str, tool_name: str, arguments_digest: str, risk_score: int) -> str | None:
    approval_id = str(uuid.uuid4())
    now = _now()
    try:
        ok = get_store().create_approval(
            approval_id, scan_id, tool_name, arguments_digest, risk_score,
            now.isoformat(), (now + timedelta(seconds=settings.approval_ttl_seconds)).isoformat())
        return approval_id if ok else None
    except Exception as e:
        logger.warning(f"Could not record approval request: {e}")
        return None


def get_approval(approval_id: str) -> dict | None:
    try:
        return get_store().get_approval(approval_id, _now().isoformat())
    except Exception as e:
        logger.warning(f"Approval lookup failed: {e}")
        return None


def list_pending(limit: int = 50) -> list[dict]:
    try:
        return get_store().list_pending_approvals(_now().isoformat(), limit)
    except Exception as e:
        logger.warning(f"Pending approval listing failed: {e}")
        return []


def decide(approval_id: str, approved: bool, decided_by: str, reason: str = "") -> tuple[dict | None, bool]:
    """Returns (record, applied). `applied` is False when the record was
    already terminal. The transition is now ATOMIC in the storage layer --
    a conditional UPDATE on status='pending' -- so two concurrent deciders
    cannot both succeed. Previously this was a read-then-write with a
    window between them."""
    try:
        return get_store().decide_approval(approval_id, approved, decided_by, reason, _now().isoformat())
    except Exception as e:
        logger.warning(f"Approval decision failed: {e}")
        return None, False


def permits_execution(approval_id: str) -> bool:
    """The single question the enforcement path asks. Anything other than an
    explicit APPROVED -- pending, denied, expired, missing, or a store error
    -- returns False."""
    record = get_approval(approval_id)
    if record is None:
        return False
    return record["status"] in {s.value for s in PERMITS_EXECUTION}
