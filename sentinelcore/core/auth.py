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

from enum import Enum

from fastapi import Header, HTTPException, status

from sentinelcore.core.config import settings


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
