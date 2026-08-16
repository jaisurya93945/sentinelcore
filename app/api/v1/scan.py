"""
Scan endpoint.

Runs every registered detector against the input, then the Risk Engine and
Policy Engine to produce a final risk score and decision. This is the full
Phase 3 pipeline (detect -> score -> decide) -- no longer a "preview" that
leaves risk_score/decision null.
"""

from fastapi import APIRouter

from app.detectors.registry import get_registered_detectors
from app.models.finding import ScanRequest, ScanResult
from app.services.policy_engine import decide
from app.services.risk_engine import calculate_risk_score

router = APIRouter()


@router.post("/scan", response_model=ScanResult)
def scan(payload: ScanRequest) -> ScanResult:
    result = ScanResult(input_text=payload.text)

    for detector_cls in get_registered_detectors().values():
        detector = detector_cls()
        result.findings.extend(detector.detect(payload.text, payload.context))

    result.risk_score = calculate_risk_score(result.findings)
    result.decision = decide(result.findings, result.risk_score)

    return result
