"""
MCP tool discovery scanning.

Scans MCP tool definitions -- as they'd appear in a real `tools/list`
response -- for tool poisoning: hidden instructions embedded in a tool's
description, designed to manipulate the model when it reads the tool
catalog, before the tool is ever called. This is a real, documented MCP
attack class, not a hypothetical: MCP's own documentation states plainly
that a tool's description "is part of the prompt context sent to the
model... it serves as the instruction manual for the AI" -- which is
exactly why attacker-controlled text there is dangerous.

Deliberately reuses the existing detector registry rather than building
new detection logic -- a poisoned description is still just injected
text, the same thing prompt_injection already looks for. What's new is
*where* it looks: recursively through every description field in a tool
definition, not just the top-level one. MCP tool schemas nest
descriptions per-property too, and property descriptions are shown to
the model exactly the same way -- so a poisoned property description is
just as real an attack surface as a poisoned top-level one.
"""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from sentinelcore.core.auth import Role, require_role
from sentinelcore.detectors.registry import get_registered_detectors
from sentinelcore.models.finding import Finding, MCPToolResult, MCPToolScanRequest, MCPToolScanResult
from sentinelcore.services.audit_log import log_scan_event
from sentinelcore.services.policy_engine import decide
from sentinelcore.services.risk_engine import calculate_risk_score

router = APIRouter(dependencies=[Depends(require_role(Role.OPERATOR))])


def _extract_schema_descriptions(schema: Any) -> list[str]:
    """Recursively pull every 'description' string out of a JSON Schema
    object. MCP tool descriptions live at the top level AND per-property
    within inputSchema, and both are shown to the model."""
    descriptions: list[str] = []
    if isinstance(schema, dict):
        if isinstance(schema.get("description"), str):
            descriptions.append(schema["description"])
        for value in schema.values():
            descriptions.extend(_extract_schema_descriptions(value))
    elif isinstance(schema, list):
        for item in schema:
            descriptions.extend(_extract_schema_descriptions(item))
    return descriptions


def _scan_text(text: str, origin: str) -> list[Finding]:
    findings: list[Finding] = []
    for cls in get_registered_detectors().values():
        detected = cls().detect(text)
        for f in detected:
            f.origin = origin
        findings.extend(detected)
    return findings


class MCPPinRequest(MCPToolScanRequest):
    server: str


@router.post("/mcp/pin", dependencies=[Depends(require_role(Role.ADMIN))])
def pin(payload: MCPPinRequest):
    """Establish or refresh a server's baseline.

    ADMIN, not operator: re-pinning after a detected change is how an
    operator says "I reviewed this and accept it". Making it available to
    the role that merely observes would let a change be silently blessed by
    whoever noticed it."""
    from sentinelcore.services.mcp_pinning import pin_tools

    return pin_tools(payload.server, [t.model_dump() for t in payload.tools])


@router.post("/mcp/check", dependencies=[Depends(require_role(Role.OPERATOR))])
def check(payload: MCPPinRequest):
    """Compare an observed tool list against the baseline.

    Detected changes are recorded and alerted. The response carries the
    trust-on-first-use limitation explicitly -- a caller must not read
    'clean' as 'this server is safe'."""
    from sentinelcore.services.mcp_pinning import check_tools

    result = check_tools(payload.server, [t.model_dump() for t in payload.tools])

    # A definition change is exactly the kind of event nobody is watching a
    # dashboard for. Route it through the existing alert path.
    if result["changes"]:
        from sentinelcore.services.alerts import Alert, get_manager

        mgr = get_manager()
        worst = "high" if any(c["severity"] == "high" for c in result["changes"]) else "medium"
        alert = Alert(
            timestamp=result["changes"][0]["detected_at"],
            scan_id=f"mcp-{payload.server}",
            endpoint="mcp_pin_check",
            decision="block" if worst == "high" else "warn",
            risk_score=90 if worst == "high" else 50,
            finding_types=sorted({c["change_type"] for c in result["changes"]}),
            detail=payload.server,
        )
        try:
            mgr._queue.put_nowait(alert)
            mgr._ensure_worker()
            with mgr._lock:
                mgr.stats.dispatched += 1
        except Exception:
            pass
    return result


@router.get("/mcp/pins", dependencies=[Depends(require_role(Role.VIEWER))])
def pins(server: str | None = None):
    from sentinelcore.services.mcp_pinning import get_store

    return {"pins": get_store().list_mcp_pins(server)}


@router.get("/mcp/changes", dependencies=[Depends(require_role(Role.VIEWER))])
def changes(unacknowledged_only: bool = True, limit: int = 100):
    from sentinelcore.services.mcp_pinning import get_store

    return {"changes": get_store().list_mcp_changes(
        acknowledged=False if unacknowledged_only else None, limit=limit)}


@router.post("/mcp/changes/{change_id}/acknowledge",
             dependencies=[Depends(require_role(Role.ADMIN))])
def acknowledge(change_id: str):
    """Marks a change reviewed. Deliberately does NOT re-pin: accepting that
    a change happened is a different decision from trusting the new
    definition, and conflating them would turn review into approval."""
    from sentinelcore.services.mcp_pinning import acknowledge as ack

    if not ack(change_id):
        raise HTTPException(status_code=404, detail="No such unacknowledged change.")
    return {"id": change_id, "acknowledged": True}


@router.post("/scan/mcp-tools", response_model=MCPToolScanResult)
def scan_mcp_tools(payload: MCPToolScanRequest) -> MCPToolScanResult:
    result = MCPToolScanResult()

    for tool in payload.tools:
        texts = [tool.description] + _extract_schema_descriptions(tool.inputSchema)
        findings: list[Finding] = []
        for text in texts:
            if text:
                findings.extend(_scan_text(text, origin=f"tool_description:{tool.name}"))

        risk_score = calculate_risk_score(findings)
        decision = decide(findings, risk_score)

        result.tools.append(MCPToolResult(name=tool.name, findings=findings, risk_score=risk_score, decision=decision))
        log_scan_event(result.scan_id, "mcp_tools", risk_score, decision.value, findings, detail=tool.name)

    return result
