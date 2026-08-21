"""
Tool-call scanning endpoint.

Combines two independent checks, per tool call:

1. Tool NAME authorization (app/services/tool_policy.py) -- a
   deterministic allow/warn/sanitize/human_approval/block lookup by tool
   name. Not risk-scored, on purpose: this is the "the LLM must never be
   the ultimate authorization authority" principle in code -- an agent
   asking to call payment.transfer gets checked against a fixed policy,
   not a severity calculation.
2. Content scanning (the same detector registry as everything else) on
   the serialized arguments (origin='tool_arguments') and, if provided,
   the tool's response (origin='tool_response') -- a tool response is
   untrusted input, exactly like a RAG-retrieved document.

The final decision is the more severe of the two, arrived at
independently -- a perfectly clean argument doesn't override a denied
tool name, and an allowed tool name doesn't suppress a real finding in
its arguments.
"""

import json

from fastapi import APIRouter

from app.detectors.registry import get_registered_detectors
from app.models.finding import Finding, ToolCallRequest, ToolCallResult
from app.services.audit_log import log_scan_event
from app.services.policy_engine import decide, most_severe
from app.services.risk_engine import calculate_risk_score
from app.services.tool_policy import authorize_tool

router = APIRouter()


def _scan_text(text: str, origin: str) -> list[Finding]:
    findings: list[Finding] = []
    for cls in get_registered_detectors().values():
        detected = cls().detect(text)
        for f in detected:
            f.origin = origin
        findings.extend(detected)
    return findings


@router.post("/scan/tool-call", response_model=ToolCallResult)
def scan_tool_call(payload: ToolCallRequest) -> ToolCallResult:
    findings = _scan_text(json.dumps(payload.arguments), origin="tool_arguments")
    if payload.response:
        findings.extend(_scan_text(payload.response, origin="tool_response"))

    risk_score = calculate_risk_score(findings)
    content_decision = decide(findings, risk_score)
    tool_decision = authorize_tool(payload.tool_name)
    final_decision = most_severe([content_decision, tool_decision])

    result = ToolCallResult(
        tool_name=payload.tool_name,
        tool_authorization=tool_decision,
        findings=findings,
        risk_score=risk_score,
        decision=final_decision,
    )
    log_scan_event(result.scan_id, "tool_call", risk_score, final_decision.value, findings, detail=payload.tool_name)
    return result
