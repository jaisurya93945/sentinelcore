"""
Audit query endpoint.

Read-only access to the metadata-only audit log -- see
sentinelcore/services/audit_log.py for exactly what is and isn't stored (no raw
text, ever).
"""

from fastapi import APIRouter, Depends, HTTPException, Query

from sentinelcore.core.auth import Role, require_role
from sentinelcore.services.audit_log import get_recent_events

router = APIRouter(dependencies=[Depends(require_role(Role.VIEWER))])


@router.get("/storage/health", dependencies=[Depends(require_role(Role.VIEWER))])
def storage_status():
    """Backend, schema version, reachability and failure counters.

    Never raises: an operator asking "is the audit log working?" must get an
    answer precisely when it is not. Connection strings are redacted by the
    backend before they reach this response."""
    from sentinelcore.storage import storage_health

    return storage_health()


@router.post("/storage/retention/run", dependencies=[Depends(require_role(Role.ADMIN))])
def run_retention():
    """Force a retention pass. Admin-only: it deletes data."""
    from sentinelcore.storage import current_policy, get_store

    try:
        return {"deleted": get_store().apply_retention(current_policy()),
                "policy": current_policy().__dict__}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"storage unavailable: {type(e).__name__}")


@router.get("/alerts/status", dependencies=[Depends(require_role(Role.VIEWER))])
def alert_status():
    """Operational visibility on the alert path itself. An alerting system
    whose own failures are invisible is not much better than none: dropped
    and suppressed counts are how an operator discovers their webhook has
    been down all week."""
    from sentinelcore.services.alerts import get_manager

    mgr = get_manager()
    return {
        "sinks": mgr.sink_names,
        "triggers": sorted(d.value for d in mgr.triggers),
        "cooldown_seconds": mgr.cooldown_seconds,
        "stats": mgr.stats.__dict__,
    }


@router.get("/audit/recent")
def recent_audit_events(limit: int = Query(default=50, ge=1, le=500)):
    return {"events": get_recent_events(limit=limit)}
