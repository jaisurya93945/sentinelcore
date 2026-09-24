"""
Authentication and role-based authorization.

Real and working, but OFF by default: if SENTINELCORE_API_KEYS is unset,
every endpoint behaves exactly as it did before this existed -- no key
required. This is what keeps every existing test and the "just run it
locally" quickstart working unchanged. It also means: running this
network-reachable without setting API keys is a real, named risk, not a
safe default -- stated here plainly, not left implicit. See
docs/threat-model/README.md.

Three roles, not the five the original hardening spec sketched (Viewer/
Auditor/Operator/Administrator/Service). Collapsed deliberately: this
project has no admin-configurable state and no per-tool service
identities yet, so five labels would describe three real permission
levels. Documented here, not silently simplified without saying so.

    viewer   -- read the audit trail and dashboard only
    operator -- viewer + call scan/tool-call/mcp/proxy endpoints
    admin    -- operator + reserved for future admin-only operations

Format: SENTINELCORE_API_KEYS="key1:viewer,key2:operator,key3:admin"
"""

import logging
from enum import Enum

from fastapi import Header, HTTPException, status

from sentinelcore.core.config import settings

logger = logging.getLogger(__name__)


class Role(str, Enum):
    VIEWER = "viewer"
    OPERATOR = "operator"
    ADMIN = "admin"


_ROLE_RANK = {Role.VIEWER: 0, Role.OPERATOR: 1, Role.ADMIN: 2}


def parse_api_keys() -> dict[str, Role]:
    """Parses SENTINELCORE_API_KEYS. Unrecognized role names are skipped
    (not silently granted access) so a typo in config fails safe."""
    raw = settings.api_keys.strip()
    if not raw:
        return {}
    parsed: dict[str, Role] = {}
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry or ":" not in entry:
            continue
        key, _, role_str = entry.partition(":")
        key = key.strip()
        try:
            role = Role(role_str.strip().lower())
        except ValueError:
            continue
        if key:
            parsed[key] = role
    return parsed


def resolve_principal(api_key: str | None):
    """Maps a presented key to a Principal.

    When authentication is disabled there is one implicit principal in the
    default tenant. That is correct for local use and is exactly why
    `sentinel assess` reports disabled auth as a HIGH finding: with no
    credential there is no identity, and with no identity there is no
    tenant isolation."""
    from sentinelcore.core.identity import ANONYMOUS, parse_principals

    principals = parse_principals()
    if not principals:
        return ANONYMOUS
    return principals.get((api_key or "").strip())


def require_role(minimum: Role):
    """FastAPI dependency factory. Auth is skipped entirely (request
    allowed through) if no keys are configured at all -- see module
    docstring for why that's the documented default, not a silent gap."""

    def _dependency(x_api_key: str | None = Header(default=None)) -> None:
        keys = parse_api_keys()
        if not keys:
            return
        if not x_api_key or x_api_key not in keys:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing API key.")
        if _ROLE_RANK[keys[x_api_key]] < _ROLE_RANK[minimum]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role for this endpoint.")

    return _dependency

def unauthenticated_exposure() -> str | None:
    """Describes what is reachable without credentials, or None if auth is on.

    Auth is off by default and that default is documented -- but a note in
    a repository is not a runtime control. The shipped Dockerfile binds
    0.0.0.0:8000, so `docker run` produces a gateway whose OWN security
    controls are open: measured with no keys configured, GET
    /api/v1/mcp/pins and GET /api/v1/audit/recent both return data to an
    anonymous caller. Anyone on the network can read the audit trail, and
    the role checks that would stop them re-pinning an MCP baseline or
    deciding a pending approval are skipped entirely.

    Nothing told the operator. This is what tells them.
    """
    if parse_api_keys():
        return None
    return (
        "No API keys are configured, so SENTINELCORE_API_KEYS is empty and every "
        "role check is skipped. The audit log, MCP baselines, approval decisions "
        "and all scan endpoints are reachable by any caller that can open a "
        "socket. The shipped container binds 0.0.0.0. Set SENTINELCORE_API_KEYS "
        "as 'key:role[,key:role...]' with roles viewer|operator|admin."
    )


def enforce_auth_required() -> None:
    """Refuse to start unauthenticated outside development.

    A warning is the right response in development, where running without
    keys is deliberate and convenient. Outside it, an unauthenticated
    security gateway is far more likely to be an accident than a choice --
    nobody decides that the audit trail should be world-readable. So the
    same condition that merely warns locally is fatal once someone has
    said this is not development.

    Escape hatch, because refusing to start is a serious thing to do:
    SENTINELCORE_ALLOW_UNAUTHENTICATED=true. It has to be set deliberately,
    which is the entire point -- the failure mode being prevented is
    nobody having thought about it at all.
    """
    exposure = unauthenticated_exposure()
    if exposure is None:
        return

    if settings.environment.strip().lower() in ("development", "dev", "local", "test", ""):
        logger.warning("SentinelCore is running UNAUTHENTICATED. %s", exposure)
        return

    if settings.allow_unauthenticated:
        logger.warning(
            "SentinelCore is running UNAUTHENTICATED in environment=%r because "
            "SENTINELCORE_ALLOW_UNAUTHENTICATED is set. %s", settings.environment, exposure)
        return

    raise RuntimeError(
        f"Refusing to start: environment={settings.environment!r} and no API keys are "
        f"configured. {exposure} If this is deliberate, set "
        f"SENTINELCORE_ALLOW_UNAUTHENTICATED=true."
    )
