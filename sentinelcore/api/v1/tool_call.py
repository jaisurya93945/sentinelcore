"""
Tool-call scanning endpoint.

Combines two independent checks, per tool call:

1. Tool NAME authorization (sentinelcore/services/tool_policy.py) -- a
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

import hashlib
import json

from fastapi import APIRouter, Depends

from sentinelcore.core.auth import Role, require_role
from sentinelcore.detectors.registry import get_registered_detectors
from sentinelcore.models.finding import Decision, EnforcementStatus, Finding, ToolCallRequest, ToolCallResult
from sentinelcore.services.audit_log import log_scan_event
from sentinelcore.services.policy_engine import decide, most_severe
from sentinelcore.services.risk_engine import calculate_risk_score
from sentinelcore.services.approvals import request_approval
from sentinelcore.services.sanitizer import enforce_sanitize_arguments
from sentinelcore.services.tool_policy import authorize_tool
from sentinelcore.core.textextract import extract_scannable_text
from sentinelcore.core.metrics import record_scan

router = APIRouter(dependencies=[Depends(require_role(Role.OPERATOR))])


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
    # NOT json.dumps: it escapes non-ASCII back to ASCII, so zero-width,
    # bidi and homoglyph payloads reached the detector already defanged and
    # produced no findings. See sentinelcore/core/textextract.py.
    findings = _scan_text(extract_scannable_text(payload.arguments), origin="tool_arguments")
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

    # HUMAN_APPROVAL used to be returned with nothing behind it. It now
    # creates a real, queryable approval record. Until a human decides it,
    # the action is NOT authorised -- and if the store is unavailable the
    # id is None, which callers must treat as refusal, not as consent.
    # SANITIZE used to fall through here with nothing behind it: the
    # response said "sanitize" while carrying no sanitized arguments and
    # enforcement_status NOT_APPLICABLE. Callers following the decision had
    # nothing to act on; callers treating not-BLOCK as permission forwarded
    # the original arguments. Now it is carried out, re-scanned, and
    # escalated if the cleaned form still trips the policy.
    if final_decision == Decision.SANITIZE:
        san = enforce_sanitize_arguments(payload.arguments, findings)
        result.enforcement_status = san.enforcement_status
        result.findings = san.findings
        result.risk_score = san.risk_score
        # The tool-NAME verdict is independent and still binds: sanitizing
        # an argument does not make a denied tool callable.
        result.decision = most_severe([san.decision, tool_decision])
        final_decision = result.decision
        if san.enforcement_status in (EnforcementStatus.ENFORCED, EnforcementStatus.ESCALATED):
            result.sanitized_arguments = san.sanitized_arguments

    if final_decision == Decision.HUMAN_APPROVAL:
        digest = hashlib.sha256(json.dumps(payload.arguments, sort_keys=True).encode()).hexdigest()[:16]
        result.approval_id = request_approval(result.scan_id, payload.tool_name, digest, risk_score)
        result.enforcement_status = (
            EnforcementStatus.PENDING_APPROVAL if result.approval_id else EnforcementStatus.NOT_IMPLEMENTED
        )
    record_scan("tool_call", final_decision.value, findings=result.findings,
                enforcement_status=result.enforcement_status.value)
    log_scan_event(result.scan_id, "tool_call", risk_score, final_decision.value, findings, detail=payload.tool_name)
    return result
