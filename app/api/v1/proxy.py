"""
OpenAI-compatible /v1/chat/completions reverse proxy.

Point an existing OpenAI-SDK-compatible client's base_url at this gateway
instead of directly at your LLM provider -- requests are scanned before
being forwarded, AND the response is scanned before being returned. A
BLOCK decision on either side means the caller never sees the content.

Streaming (stream=true) is explicitly not supported yet -- rejected with
a clear error rather than silently mishandled. See docs/threat-model/README.md
for this and every other documented limitation of the proxy.
"""

import json
import uuid

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from app.detectors.registry import get_registered_detectors
from app.models.finding import Decision, Finding
from app.services.audit_log import log_scan_event
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


def _scan_text(text: str, origin: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for cls in get_registered_detectors().values():
        detected = cls().detect(text)
        if origin:
            for f in detected:
                f.origin = origin
        findings.extend(detected)
    return findings


def _scan_messages(messages: list[dict]) -> list[Finding]:
    """Scan the latest user message as 'input' and any tool-role messages
    (typically retrieved/RAG content in real integrations) as 'context' --
    the same origin convention as /api/v1/scan."""
    findings: list[Finding] = []

    user_texts = [_extract_text(m.get("content")) for m in messages if m.get("role") == "user"]
    latest_user_text = user_texts[-1] if user_texts else ""
    findings.extend(_scan_text(latest_user_text))

    tool_texts = [_extract_text(m.get("content")) for m in messages if m.get("role") == "tool"]
    for i, doc_text in enumerate(tool_texts):
        findings.extend(_scan_text(doc_text, origin=f"context:{i}"))

    return findings


def _extract_assistant_text(upstream_content: bytes) -> str | None:
    """Best-effort extraction of the assistant's reply from an OpenAI-shaped
    chat completion response. Returns None on anything unexpected -- output
    scanning is skipped rather than guessed at, and the response still
    passes through normally."""
    try:
        body = json.loads(upstream_content)
        content = body["choices"][0]["message"]["content"]
        return content if isinstance(content, str) else None
    except (json.JSONDecodeError, KeyError, IndexError, TypeError):
        return None


def _blocked_response(findings: list[Finding], risk_score: int, decision: Decision, stage: str) -> JSONResponse:
    return JSONResponse(
        status_code=400,
        content={
            "error": {
                "message": f"{'Request' if stage == 'input' else 'Response'} blocked by SentinelCore gateway.",
                "type": f"sentinelcore_{stage}_blocked",
            },
            "sentinelcore": {
                "decision": decision.value,
                "risk_score": risk_score,
                "findings": [f.model_dump(mode="json") for f in findings],
            },
        },
        headers={
            f"X-SentinelCore-{stage.capitalize()}-Decision": decision.value,
            f"X-SentinelCore-{stage.capitalize()}-Risk-Score": str(risk_score),
        },
    )


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
    input_findings = _scan_messages(messages) if isinstance(messages, list) else []

    input_risk_score = calculate_risk_score(input_findings)
    input_decision = decide(input_findings, input_risk_score)

    scan_id = str(uuid.uuid4())  # shared by both log entries for this request
    log_scan_event(scan_id, "proxy_input", input_risk_score, input_decision.value, input_findings)

    if input_decision == Decision.BLOCK:
        return _blocked_response(input_findings, input_risk_score, input_decision, stage="input")

    # ALLOW / WARN / SANITIZE on the input side -- sanitize execution isn't
    # implemented yet, so this currently behaves like allow-with-a-header.
    upstream_response = await forward_to_upstream(
        path="/v1/chat/completions",
        method="POST",
        headers=dict(request.headers),
        body=raw_body,
    )

    # Output scan: the upstream call has already happened at this point --
    # unlike an input BLOCK, an output BLOCK still incurs the upstream cost.
    # That's a real limitation of post-hoc output filtering, not an oversight.
    assistant_text = _extract_assistant_text(upstream_response.content)
    output_findings = _scan_text(assistant_text, origin="output") if assistant_text else []
    output_risk_score = calculate_risk_score(output_findings)
    output_decision = decide(output_findings, output_risk_score)
    log_scan_event(scan_id, "proxy_output", output_risk_score, output_decision.value, output_findings)

    if output_decision == Decision.BLOCK:
        return _blocked_response(output_findings, output_risk_score, output_decision, stage="output")

    response_headers = dict(upstream_response.headers)
    response_headers["X-SentinelCore-Input-Decision"] = input_decision.value
    response_headers["X-SentinelCore-Input-Risk-Score"] = str(input_risk_score)
    response_headers["X-SentinelCore-Output-Decision"] = output_decision.value
    response_headers["X-SentinelCore-Output-Risk-Score"] = str(output_risk_score)
    # Recalculated by Starlette for the returned Response -- forwarding the
    # upstream's original value can mismatch once headers are added.
    response_headers.pop("content-length", None)
    response_headers.pop("Content-Length", None)

    return Response(
        content=upstream_response.content,
        status_code=upstream_response.status_code,
        headers=response_headers,
    )
