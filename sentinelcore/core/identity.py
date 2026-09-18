"""
Principals and tenant scoping.

WHY THIS EXISTS
Until now `decided_by` on an approval was a free-text string the caller
supplied. The dashboard said so in its own prompt, and the API schema
called it UNVERIFIED -- honest, but it means the audit trail records a
claim rather than a fact. An approval workflow whose record of *who
approved* is self-asserted is a workflow an attacker can forge the
provenance of.

THE MODEL, deliberately small
SentinelCore is not an identity provider and should not become one. A
principal is derived entirely from the credential already presented:

    SENTINELCORE_API_KEYS="key:role"                     -> tenant 'default'
    SENTINELCORE_API_KEYS="key:role:tenant"              -> named tenant
    SENTINELCORE_API_KEYS="key:role:tenant:principal_id" -> named actor

Every form remains valid, so existing deployments keep working unchanged
and land in the `default` tenant. The principal id defaults to a stable
fingerprint of the key -- never the key itself, which must not reach an
audit record or a log.

WHY TENANT IS AMBIENT, NOT A PARAMETER
Passing tenant into each storage call means one forgotten call site is a
cross-tenant leak, and the roadmap's own warning was that partial
isolation is worse than none. The tenant therefore lives in a ContextVar
set once by the auth layer, and the storage backends read it internally.
A test then asserts that every query against a tenant-scoped table carries
a tenant predicate -- so a new query that forgets to scope fails CI rather
than leaking quietly.

ContextVar rather than thread-local for the same reason as detector
selection: it is isolated per thread AND per asyncio task.
"""

import hashlib
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass

from sentinelcore.core.config import settings

DEFAULT_TENANT = "default"

# Tables whose rows belong to a tenant. Anything added here must also be
# scoped in both backends; test_tenancy.py enforces that.
TENANT_SCOPED_TABLES = ("scan_events", "approvals", "feedback", "mcp_pins", "mcp_changes")


@dataclass(frozen=True)
class Principal:
    principal_id: str
    tenant: str
    role: str

    @property
    def is_anonymous(self) -> bool:
        return self.principal_id == "anonymous"


ANONYMOUS = Principal(principal_id="anonymous", tenant=DEFAULT_TENANT, role="admin")

_current: ContextVar[Principal] = ContextVar("sentinelcore_principal", default=ANONYMOUS)


def key_fingerprint(key: str) -> str:
    """Stable, non-reversible identifier for a key.

    Used when a deployment does not name principals explicitly. The raw key
    must never appear in an audit record, an alert, or a log -- a security
    tool that writes its own credentials into its audit trail has created
    the problem it exists to prevent.
    """
    return "key-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]


def parse_principals() -> dict[str, Principal]:
    """Parses SENTINELCORE_API_KEYS into principals.

    Accepts key:role, key:role:tenant and key:role:tenant:principal_id.
    An unrecognised role is SKIPPED rather than defaulted, so a typo in
    configuration removes access instead of silently granting it.
    """
    from sentinelcore.core.auth import Role

    raw = (settings.api_keys or "").strip()
    if not raw:
        return {}
    out: dict[str, Principal] = {}
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry or ":" not in entry:
            continue
        parts = [p.strip() for p in entry.split(":")]
        key, role_str = parts[0], parts[1] if len(parts) > 1 else ""
        if not key:
            continue
        try:
            role = Role(role_str.lower())
        except ValueError:
            continue
        tenant = parts[2] if len(parts) > 2 and parts[2] else DEFAULT_TENANT
        pid = parts[3] if len(parts) > 3 and parts[3] else key_fingerprint(key)
        out[key] = Principal(principal_id=pid, tenant=tenant, role=role.value)
    return out


def current() -> Principal:
    return _current.get()


def current_tenant() -> str:
    return _current.get().tenant


@contextmanager
def acting_as(principal: Principal):
    """Scopes the principal to one call. Set by the auth dependency for a
    request; used directly by the CLI and by tests."""
    token = _current.set(principal)
    try:
        yield principal
    finally:
        _current.reset(token)


def set_principal(principal: Principal):
    """Non-contextmanager form for middleware that cannot wrap the call.
    Returns the token so the caller can reset it."""
    return _current.set(principal)


def reset_principal(token) -> None:
    _current.reset(token)
