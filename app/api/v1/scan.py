"""
Preview scan endpoint.

Runs every registered detector against the input and returns raw findings.
Risk scoring and policy decisions are NOT implemented yet (Phase 3) --
`risk_score` and `decision` are intentionally left null rather than faked.
"""

from fastapi import APIRouter

from app.detectors.registry import get_registered_detectors
from app.models.finding import ScanRequest, ScanResult

router = APIRouter()


@router.post("/scan", response_model=ScanResult)
def scan(payload: ScanRequest) -> ScanResult:
    result = ScanResult(input_text=payload.text)

    for detector_cls in get_registered_detectors().values():
        detector = detector_cls()
        result.findings.extend(detector.detect(payload.text, payload.context))

    return result
