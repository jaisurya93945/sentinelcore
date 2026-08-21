"""
Dashboard.

Serves a single static, read-only HTML page that polls GET
/api/v1/audit/recent and renders it -- no separate build pipeline, no
new dependency, no server-side state of its own. It reads the same
metadata-only audit trail described in app/services/audit_log.py, so
everything that file promises never gets stored (raw text, finding
evidence) never appears here either, by construction rather than by
extra care in this file.
"""

from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter()

_DASHBOARD_PATH = Path(__file__).parent.parent.parent / "static" / "dashboard.html"


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return _DASHBOARD_PATH.read_text(encoding="utf-8")
