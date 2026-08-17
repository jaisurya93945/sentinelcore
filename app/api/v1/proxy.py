"""
OpenAI-compatible /v1/chat/completions reverse proxy.

Point an existing OpenAI-SDK-compatible client's base_url at this gateway
instead of directly at your LLM provider -- requests are scanned before
being forwarded. A BLOCK decision never reaches the upstream model at all.

Streaming (stream=true) is explicitly not supported yet -- rejected with
a clear error rather than silently mishandled. See docs/threat-model/README.md
for this and every other documented limitation of the proxy.
"""

import json

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from app.detectors.registry import get_registered_detectors
from app.models.finding import Decision, Finding
from app.services.policy_engine import decide
from app.services.proxy import forward_to_upstream
from app.services.risk_engine import calculate_risk_score

router = APIRouter()


def _extract_text(content) -> str:
    """Message content can be a plain string or a list of content parts
    (multimodal). Extract and join any text parts; non-text parts
    (images, audio, etc.) are not inspected in v0.1."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return " ".join(
            part.get("text", "") for part in content if isinstance(part, dict) and part.get("type") == "text"
        )
    return ""


def _scan_messages(messages: list[dict]) -> list[Finding]:
    """Scan the latest user message as 'input' and any tool-role messages
    (typically retrieved/RAG content in real integrations) as 'context' --
    the same origin convention as /api/v1/scan."""
    detectors = get_registered_detectors()
    findings: list[Finding] = []

    user_texts = [_extract_text(m.get("content")) for m in messages if m.get("role") == "user"]
    latest_user_text = user_texts[-1] if user_texts else ""
    for cls in detectors.values():
        findings.extend(cls().detect(latest_user_text))

    tool_texts = [_extract_text(m.get("content")) for m in messages if m.get("role") == "tool"]
    for i, doc_text in enumerate(tool_texts):
        for cls in detectors.values():
            doc_findings = cls().detect(doc_text)
            for f in doc_findings:
                f.origin = f"context:{i}"
            findings.extend(doc_findings)

    return findings


@router.post("/chat/completions")
async def chat_completions(request: Request):
    raw_body = await request.body()

    try:
        body = json.loads(raw_body)
    except json.JSONDecodeError:
        return JSONResponse(
            status_code=400,
            content={"error": {"message": "Invalid JSON body.", "type": "sentinelcore_invalid_request"}},
        )

    if body.get("stream"):
        return JSONResponse(
            status_code=501,
            content={
                "error": {
                    "message": (
                        "SentinelCore does not proxy streaming responses yet (v0.1). "
                        "Set stream=false, or scan content yourself via /api/v1/scan before streaming."
                    ),
                    "type": "sentinelcore_not_implemented",
                }
            },
        )

    messages = body.get("messages")
    # Malformed/unrecognized bodies (no messages list) are forwarded through
    # unscanned rather than blocked -- a documented v0.1 limitation, not a
    # silent gap. See docs/threat-model/README.md.
    findings = _scan_messages(messages) if isinstance(messages, list) else []

    risk_score = calculate_risk_score(findings)
    decision = decide(findings, risk_score)

    if decision == Decision.BLOCK:
        return JSONResponse(
            status_code=400,
            content={
                "error": {
                    "message": "Request blocked by SentinelCore gateway.",
                    "type": "sentinelcore_blocked",
                },
                "sentinelcore": {
                    "decision": decision.value,
                    "risk_score": risk_score,
                    "findings": [f.model_dump(mode="json") for f in findings],
                },
            },
            headers={"X-SentinelCore-Decision": decision.value, "X-SentinelCore-Risk-Score": str(risk_score)},
        )

    # ALLOW / WARN / SANITIZE -- sanitize execution (stripping the flagged
    # content and re-checking) is not implemented yet, so this currently
    # behaves like allow-with-a-diagnostic-header. Documented, not hidden.
    upstream_response = await forward_to_upstream(
        path="/v1/chat/completions",
        method="POST",
        headers=dict(request.headers),
        body=raw_body,
    )

    response_headers = dict(upstream_response.headers)
    response_headers["X-SentinelCore-Decision"] = decision.value
    response_headers["X-SentinelCore-Risk-Score"] = str(risk_score)
    # Recalculated by Starlette for the returned Response -- forwarding the
    # upstream's original value can mismatch once headers are added.
    response_headers.pop("content-length", None)
    response_headers.pop("Content-Length", None)

    return Response(
        content=upstream_response.content,
        status_code=upstream_response.status_code,
        headers=response_headers,
    )
