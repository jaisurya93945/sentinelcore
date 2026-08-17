"""
Scan endpoint.

Runs every registered detector against the main input, then the Risk
Engine and Policy Engine to produce a final risk score and decision.

Also scans any RAG-retrieved documents for indirect prompt injection --
the same well-known attack class where a malicious webpage or document
gets retrieved into context and its hidden instructions get treated as
real ones. This deliberately reuses the existing detectors rather than
adding a new one: the detection logic doesn't change, only *where* it
looks. Findings from retrieved documents are tagged origin='context:<i>'
so a reviewer can immediately tell "the user wrote this" apart from
"a retrieved document said this".
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

    result.risk_score = calculate_risk_score(result.findings)
    result.decision = decide(result.findings, result.risk_score)

    return result
