"""
Audit query endpoint.

Read-only access to the metadata-only audit log -- see
app/services/audit_log.py for exactly what is and isn't stored (no raw
text, ever).
"""

from fastapi import APIRouter, Query

from app.services.audit_log import get_recent_events

router = APIRouter()


@router.get("/audit/recent")
def recent_audit_events(limit: int = Query(default=50, ge=1, le=500)):
    return {"events": get_recent_events(limit=limit)}
