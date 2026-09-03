"""
Scan endpoint.

Runs every registered detector against the main input, then the Risk
Engine and Policy Engine to produce a final risk score and decision.

Also scans:
- RAG-retrieved documents for indirect prompt injection (findings tagged
  origin='context:<i>')
- an optional candidate output_text for PII/secret leakage before it's
  sent anywhere (findings tagged origin='output')

Deliberately reuses the existing detectors for all three -- no separate
detection logic exists per input source, only per attack category.

If the decision is SANITIZE, this endpoint actually attempts it (see
app/services/sanitizer.py) rather than returning a decision with nothing
behind it. `decision` always reflects the final, actionable outcome
after that attempt; `enforcement_status` explains how it got there.
`findings` always shows what was found on the ORIGINAL text, as an
audit trail, regardless of what enforcement did afterward.
"""

from fastapi import APIRouter, Depends

from app.core.auth import Role, require_role
from app.detectors.registry import get_registered_detectors
from app.models.finding import Decision, EnforcementStatus, ScanRequest, ScanResult
from app.services.audit_log import log_scan_event
from app.services.policy_engine import decide
from app.services.risk_engine import calculate_risk_score
from app.services.sanitizer import enforce_sanitize

router = APIRouter(dependencies=[Depends(require_role(Role.OPERATOR))])


@router.post("/scan", response_model=ScanResult)
def scan(payload: ScanRequest) -> ScanResult:
    result = ScanResult(input_text=payload.text)
    detectors = get_registered_detectors()

    for detector_cls in detectors.values():
        result.findings.extend(detector_cls().detect(payload.text, payload.context))

    for i, doc_text in enumerate(payload.retrieved_documents or []):
        for detector_cls in detectors.values():
            doc_findings = detector_cls().detect(doc_text)
            for finding in doc_findings:
                finding.origin = f"context:{i}"
            result.findings.extend(doc_findings)

    if payload.output_text:
        for detector_cls in detectors.values():
            output_findings = detector_cls().detect(payload.output_text)
            for finding in output_findings:
                finding.origin = "output"
            result.findings.extend(output_findings)

    result.risk_score = calculate_risk_score(result.findings)
    result.decision = decide(result.findings, result.risk_score)

    if result.decision == Decision.SANITIZE:
        non_input_findings = [f for f in result.findings if f.origin != "input"]
        if non_input_findings:
            # A SANITIZE verdict influenced by retrieved-document or output
            # findings isn't something this endpoint can act on by rewriting
            # payload.text -- reported as not applicable rather than
            # sanitizing something that wouldn't actually address why the
            # decision was made.
            result.enforcement_status = EnforcementStatus.NOT_APPLICABLE
        else:
            input_findings = [f for f in result.findings if f.origin == "input"]
            sanitize_result = enforce_sanitize(payload.text, input_findings)
            result.sanitized_text = sanitize_result.sanitized_text
            result.enforcement_status = sanitize_result.enforcement_status
            result.decision = sanitize_result.decision

    log_scan_event(result.scan_id, "scan", result.risk_score, result.decision.value, result.findings)

    return result
