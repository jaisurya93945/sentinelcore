"""
Dashboard.

Serves a single static, read-only HTML page that polls GET
/api/v1/audit/recent and renders it -- no separate build pipeline, no
new dependency, no server-side state of its own. It reads the same
metadata-only audit trail described in sentinelcore/services/audit_log.py, so
everything that file promises never gets stored (raw text, finding
evidence) never appears here either, by construction rather than by
extra care in this file.
"""

from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import HTMLResponse, Response

router = APIRouter()

_DASHBOARD_PATH = Path(__file__).parent.parent.parent / "static" / "dashboard.html"


# Defence in depth for the dashboard, which renders data derived from
# attacker-controlled input (tool names, MCP server names, finding types).
# The page escapes everything at render; this header means a missed escape
# somewhere cannot execute injected script.
#
# 'unsafe-inline' for style-src only: the page ships one inline <style>
# block and no inline event handlers. script-src stays strict, which is
# what actually matters -- and a nonce would require templating the file.
_CSP = (
    "default-src 'none'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "connect-src 'self'; "
    "img-src 'self' data:; "
    "form-action 'none'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'"
)


_SCRIPT_PATH = _DASHBOARD_PATH.parent / "dashboard.js"


@router.get("/static/dashboard.js")
def dashboard_script():
    """Served separately so the page can carry script-src 'self' rather than
    'unsafe-inline'. An inline script would force the CSP to permit inline
    execution, which is precisely what defeats it as an XSS control."""
    return Response(
        _SCRIPT_PATH.read_text(encoding="utf-8"),
        media_type="application/javascript",
        headers={"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"},
    )


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return HTMLResponse(
        _DASHBOARD_PATH.read_text(encoding="utf-8"),
        headers={
            "Content-Security-Policy": _CSP,
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            # The dashboard shows security decisions; a shared cache holding
            # them would leak one tenant's activity to another.
            "Cache-Control": "no-store",
        },
    )
