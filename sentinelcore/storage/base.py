"""
Storage abstraction.

A small explicit interface, not an ORM. SentinelCore persists four kinds
of record with well-known shapes and a handful of query patterns; a query
builder would add a dependency and a layer of indirection to solve a
problem this system does not have.

FAILURE SEMANTICS -- the security-relevant part
Three things are deliberately distinct, and the distinction survives here:

    SECURITY DECISION   computed in-process, never depends on storage
    AUDIT PERSISTENCE   durable record of that decision
    NOTIFICATION        best-effort alert

A storage failure must never change a security decision, and must never be
silently invisible either. Write failures are counted and exposed through
`health()`, so "the audit database has been unwritable for a week" is a
question an operator can answer. A failed audit write does NOT imply the
decision failed, and does not imply it succeeded -- it means the record is
missing, which is exactly what gets reported.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class StorageStats:
    writes: int = 0
    write_failures: int = 0
    reads: int = 0
    read_failures: int = 0
    retention_runs: int = 0
    retention_failures: int = 0
    rows_deleted: int = 0
    last_write_error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


@dataclass
class RetentionPolicy:
    """Time-based retention with a count-based safeguard.

    Time alone is insufficient: a burst of traffic inside the retention
    window can grow the table without limit, which is the same
    unbounded-growth class already fixed in the rate limiter. The count cap
    is a second, independent bound.
    """

    audit_days: int = 30
    feedback_days: int = 365          # operator-reported cases are training data; keep longer
    approvals_days: int = 90
    max_audit_rows: int = 1_000_000   # count-based safeguard, independent of age
    enabled: bool = True


@dataclass
class QueryFilters:
    decision: str | None = None
    endpoint: str | None = None
    since: str | None = None
    limit: int = 50
    offset: int = 0


class Store(ABC):
    """Every backend implements this. Callers never import a backend.

    TENANT SCOPING IS AMBIENT. No method on this interface takes a tenant
    argument: every implementation reads it from the request context
    (`sentinelcore.core.identity.current_tenant`). That is deliberate --
    a tenant parameter means one forgotten call site is a cross-tenant
    leak, and partial isolation is worse than none because it looks like a
    boundary. `tests/unit/test_tenancy.py` parses both backends and fails
    CI on any query against a tenant-scoped table without a tenant
    predicate.

    BOTH BACKENDS MUST PROVIDE THE SAME SECURITY SEMANTICS. A backend that
    is weaker means behaviour changes silently with configuration, which a
    caller cannot reason about."""

    def __init__(self) -> None:
        self.stats = StorageStats()

    # -- lifecycle -----------------------------------------------------
    @abstractmethod
    def initialize(self) -> None:
        """Create schema and run migrations. Must be idempotent: calling it
        on an already-current database is a no-op, not an error."""

    @abstractmethod
    def close(self) -> None: ...

    @abstractmethod
    def health(self) -> dict[str, Any]:
        """Backend, schema version, reachability and the failure counters.
        The counters are the point -- a silent audit outage is worse than a
        loud one."""

    # -- audit ---------------------------------------------------------
    @abstractmethod
    def write_scan_event(self, scan_id: str, endpoint: str, risk_score: int,
                         decision: str, findings_summary: list[dict],
                         detail: str | None = None) -> bool:
        """Returns whether the record was durably written. Callers must not
        treat False as a security failure -- only as a missing record."""

    @abstractmethod
    def recent_scan_events(self, filters: QueryFilters) -> list[dict]: ...

    @abstractmethod
    def count_scan_events(self) -> int: ...

    # -- approvals -----------------------------------------------------
    @abstractmethod
    def create_approval(self, approval_id: str, scan_id: str, tool_name: str,
                        arguments_digest: str, risk_score: int,
                        created_at: str, expires_at: str) -> bool: ...

    @abstractmethod
    def get_approval(self, approval_id: str, now_iso: str) -> dict | None: ...

    @abstractmethod
    def list_pending_approvals(self, now_iso: str, limit: int) -> list[dict]: ...

    @abstractmethod
    def decide_approval(self, approval_id: str, approved: bool, decided_by: str,
                        reason: str, now_iso: str) -> tuple[dict | None, bool]:
        """Must be atomic: a PENDING record transitions exactly once, even
        under concurrent deciders."""

    # -- feedback ------------------------------------------------------
    @abstractmethod
    def write_feedback(self, feedback_id: str, scan_id: str, verdict: str,
                       note: str, submitted_by: str, submitted_at: str) -> bool: ...

    @abstractmethod
    def attach_feedback_text(self, feedback_id: str, text: str) -> bool: ...

    @abstractmethod
    def list_feedback(self, verdict: str | None, limit: int) -> list[dict]: ...

    @abstractmethod
    def feedback_counts(self) -> dict[str, int]: ...

    # -- mcp pinning ---------------------------------------------------
    @abstractmethod
    def upsert_mcp_pin(self, pin_id: str, server: str, tool_name: str,
                       fingerprint: str, definition: str, now_iso: str) -> bool:
        """Establishes or refreshes one tool's baseline.

        The identity is **(tenant, server, tool_name)** -- not
        (server, tool_name). Global uniqueness was a real isolation bug:
        two tenants pinning a server with the same name collided and one
        silently overwrote the other's baseline. The upsert must conflict
        on all three columns, and the tenant is taken from the ambient
        context rather than a parameter, so a caller cannot omit it."""

    @abstractmethod
    def list_mcp_pins(self, server: str | None = None) -> list[dict]:
        """Pins for the CURRENT tenant only. There is deliberately no
        cross-tenant listing on this interface."""

    @abstractmethod
    def record_mcp_change(self, change_id: str, **change) -> bool: ...

    @abstractmethod
    def list_mcp_changes(self, acknowledged: bool | None = None, limit: int = 100) -> list[dict]: ...

    @abstractmethod
    def acknowledge_mcp_change(self, change_id: str) -> bool: ...

    # -- retention -----------------------------------------------------
    @abstractmethod
    def apply_retention(self, policy: RetentionPolicy) -> dict[str, int]:
        """Deletes only what the policy specifies, and reports counts per
        table. Never deletes outside the configured policy."""
