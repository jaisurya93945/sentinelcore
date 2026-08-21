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

from fastapi import APIRouter

from app.detectors.registry import get_registered_detectors
from app.models.finding import Finding, MCPToolResult, MCPToolScanRequest, MCPToolScanResult
from app.services.audit_log import log_scan_event
from app.services.policy_engine import decide
from app.services.risk_engine import calculate_risk_score

router = APIRouter()


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
