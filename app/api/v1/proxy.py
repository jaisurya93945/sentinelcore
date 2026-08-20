"""
OpenAI-compatible /v1/chat/completions reverse proxy.

Point an existing OpenAI-SDK-compatible client's base_url at this gateway
instead of directly at your LLM provider -- requests are scanned before
being forwarded, AND the response is scanned before being returned. A
BLOCK decision on either side means the caller never sees the content.

Streaming (stream=true) IS supported, with real, honest tradeoffs -- see
_stream_and_scan below and docs/threat-model/README.md for what it does
and doesn't guarantee.
"""

import json
import uuid

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from app.detectors.registry import get_registered_detectors
from app.models.finding import Decision, Finding
from app.services.audit_log import log_scan_event
from app.services.policy_engine import decide
from app.services.proxy import forward_to_upstream, stream_lines_from_upstream
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


async def _stream_and_scan(scan_id: str, raw_body: bytes, headers: dict):
    """
    Streams the upstream's SSE response through to the client while
    re-scanning the accumulated text after every chunk. If a BLOCK is
    reached, stops forwarding further content and emits a synthetic
    finish_reason='content_filter' chunk -- the same field real OpenAI-
    compatible clients already understand for filtered content, not a
    SentinelCore-specific shape they'd need special handling for.

    Two tradeoffs, real and worth stating precisely rather than vaguely:
    - The specific chunk whose content triggers a BLOCK is suppressed --
      verified by test and by a live run, not assumed: it never reaches
      the client. What *can* still leak is a trigger pattern split
      across a chunk boundary (e.g. "AKIA" in one chunk, the rest of an
      AWS key in the next) -- the first chunk alone doesn't match
      anything, so it goes out before the second chunk completes the
      pattern and gets caught. Scanning faster doesn't fix this; it's a
      property of chunk boundaries not aligning with detector patterns.
    - Re-scanning the full accumulated text on every chunk is simple and
      maximally responsive, but O(n) per chunk -- O(n^2) total over a
      very long completion. Fine for typical response lengths; a real
      scaling concern for unusually long streams. An incremental
      re-scan (new content + a small overlap window) would fix this and
      isn't implemented in v1.
    """
    accumulated_text = ""
    last_findings: list[Finding] = []
    last_risk_score = 0
    last_decision = Decision.ALLOW

    async for line in stream_lines_from_upstream(
        path="/v1/chat/completions", method="POST", headers=headers, body=raw_body
    ):
        if not line.startswith("data: "):
            continue
        data_str = line[len("data: ") :]

        if data_str.strip() == "[DONE]":
            yield "data: [DONE]\n\n"
            break

        try:
            chunk = json.loads(data_str)
            delta_content = chunk["choices"][0]["delta"].get("content", "")
        except (json.JSONDecodeError, KeyError, IndexError, TypeError):
            delta_content = ""

        if delta_content:
            accumulated_text += delta_content
            last_findings = _scan_text(accumulated_text, origin="output")
            last_risk_score = calculate_risk_score(last_findings)
            last_decision = decide(last_findings, last_risk_score)

            if last_decision == Decision.BLOCK:
                yield 'data: {"choices":[{"delta":{},"finish_reason":"content_filter","index":0}]}\n\n'
                yield "data: [DONE]\n\n"
                break

        yield f"data: {data_str}\n\n"

    log_scan_event(scan_id, "proxy_output_stream", last_risk_score, last_decision.value, last_findings)


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

    if body.get("stream"):
        return StreamingResponse(
            _stream_and_scan(scan_id, raw_body, dict(request.headers)),
            media_type="text/event-stream",
            headers={
                "X-SentinelCore-Input-Decision": input_decision.value,
                "X-SentinelCore-Input-Risk-Score": str(input_risk_score),
            },
        )

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
