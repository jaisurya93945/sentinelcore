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
"""

from fastapi import APIRouter

from app.detectors.registry import get_registered_detectors
from app.models.finding import ScanRequest, ScanResult
from app.services.audit_log import log_scan_event
from app.services.policy_engine import decide
from app.services.risk_engine import calculate_risk_score

router = APIRouter()


@router.post("/scan", response_model=ScanResult)
def scan(payload: ScanRequest) -> ScanResult:
    result = ScanResult(input_text=payload.text)
    detectors = get_registered_detectors()

    # Main input -- origin defaults to "input" on the Finding model.
    for detector_cls in detectors.values():
        result.findings.extend(detector_cls().detect(payload.text, payload.context))

    # Retrieved/RAG documents -- indirect prompt injection lives here.
    for i, doc_text in enumerate(payload.retrieved_documents or []):
        for detector_cls in detectors.values():
            doc_findings = detector_cls().detect(doc_text)
            for finding in doc_findings:
                finding.origin = f"context:{i}"
            result.findings.extend(doc_findings)

    # Candidate output -- PII/secret leakage before it reaches anyone.
    if payload.output_text:
        for detector_cls in detectors.values():
            output_findings = detector_cls().detect(payload.output_text)
            for finding in output_findings:
                finding.origin = "output"
            result.findings.extend(output_findings)

    result.risk_score = calculate_risk_score(result.findings)
    result.decision = decide(result.findings, result.risk_score)
    log_scan_event(result.scan_id, "scan", result.risk_score, result.decision.value, result.findings)

    return result
