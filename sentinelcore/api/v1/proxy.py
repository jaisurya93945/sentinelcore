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

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from sentinelcore.core.auth import Role, require_role
from sentinelcore.detectors.registry import get_registered_detectors
from sentinelcore.models.finding import Decision, EnforcementStatus, Finding
from sentinelcore.services.audit_log import log_scan_event
from sentinelcore.services.policy_engine import decide, most_severe
from sentinelcore.services.proxy import forward_to_upstream, stream_lines_from_upstream
from sentinelcore.services.risk_engine import calculate_risk_score
from sentinelcore.services.sanitizer import enforce_sanitize
from sentinelcore.services.tool_policy import authorize_tool

router = APIRouter(dependencies=[Depends(require_role(Role.OPERATOR))])


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


def _extract_tool_calls(upstream_content: bytes) -> list[dict]:
    """
    Extracts model-generated tool calls from an OpenAI-shaped response.

    This exists because of a real, reproduced vulnerability: the proxy
    previously scanned only `message.content`, which is `null` whenever the
    model emits a tool call instead of prose. A response carrying
    `tool_calls: [{function: {name: "shell.execute", arguments:
    "{\\"command\\": \\"rm -rf /\\"}"}}]` passed through with decision
    "allow" -- every model-generated action bypassed the security pipeline
    entirely, even though a working tool-call scanner already existed at
    /api/v1/scan/tool-call. The gateway simply never routed to it.

    Handles both the modern `tool_calls` array and the legacy
    `function_call` object, since real clients still emit both.
    """
    try:
        body = json.loads(upstream_content)
        message = body["choices"][0]["message"]
    except (json.JSONDecodeError, KeyError, IndexError, TypeError):
        return []

    calls: list[dict] = []

    for call in message.get("tool_calls") or []:
        if not isinstance(call, dict):
            continue
        fn = call.get("function") or {}
        if isinstance(fn, dict) and fn.get("name"):
            calls.append({"name": fn["name"], "arguments": fn.get("arguments") or ""})

    legacy = message.get("function_call")
    if isinstance(legacy, dict) and legacy.get("name"):
        calls.append({"name": legacy["name"], "arguments": legacy.get("arguments") or ""})

    return calls


def _scan_tool_calls(tool_calls: list[dict]) -> tuple[list[Finding], Decision]:
    """
    Applies the same two independent checks as /api/v1/scan/tool-call:
    deterministic tool-NAME authorization (outside the model's control) and
    content scanning of the serialized arguments. Most-severe-wins across
    every call in the response -- one unauthorized call is enough to
    condemn the whole response, since the client would otherwise execute it.
    """
    if not tool_calls:
        return [], Decision.ALLOW

    all_findings: list[Finding] = []
    decisions: list[Decision] = []

    for call in tool_calls:
        name = call["name"]
        decisions.append(authorize_tool(name))

        arg_findings = _scan_text(str(call["arguments"]), origin=f"tool_arguments:{name}")
        all_findings.extend(arg_findings)
        decisions.append(decide(arg_findings, calculate_risk_score(arg_findings)))

    return all_findings, most_severe(decisions)


def _substitute_latest_user_message(body: dict, sanitized_text: str) -> bytes:
    """Rewrites the latest user message's content to the sanitized text and
    re-serializes the body -- this is what makes enforcement real rather
    than cosmetic: the modified body is what actually gets forwarded.
    Only handles plain-string content; multimodal (list) content is left
    untouched, matching _extract_text's own scope."""
    messages = body.get("messages", [])
    for message in reversed(messages):
        if message.get("role") == "user":
            if isinstance(message.get("content"), str):
                message["content"] = sanitized_text
            break
    return json.dumps(body).encode("utf-8")


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
    # Tool call arguments stream as FRAGMENTS across chunks (OpenAI sends
    # partial JSON in delta.tool_calls[].function.arguments), so scanning a
    # single chunk is meaningless -- '{"command": "rm -' matches nothing.
    # They're accumulated per index and re-scanned as they grow, which is
    # what makes mid-stream action blocking possible at all.
    accumulated_tool_calls: dict[int, dict] = {}
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

        delta_content = ""
        try:
            chunk = json.loads(data_str)
            delta = chunk["choices"][0]["delta"]
            delta_content = delta.get("content", "") or ""

            for tc in delta.get("tool_calls") or []:
                idx = tc.get("index", 0)
                slot = accumulated_tool_calls.setdefault(idx, {"name": "", "arguments": ""})
                fn = tc.get("function") or {}
                if fn.get("name"):
                    slot["name"] = fn["name"]
                if fn.get("arguments"):
                    slot["arguments"] += fn["arguments"]
        except (json.JSONDecodeError, KeyError, IndexError, TypeError):
            delta_content = ""

        if delta_content or accumulated_tool_calls:
            if delta_content:
                accumulated_text += delta_content

            content_findings = _scan_text(accumulated_text, origin="output") if accumulated_text else []
            content_score = calculate_risk_score(content_findings)
            content_decision = decide(content_findings, content_score)

            named_calls = [c for c in accumulated_tool_calls.values() if c["name"]]
            tool_findings, tool_decision = _scan_tool_calls(named_calls)

            last_findings = content_findings + tool_findings
            last_risk_score = max(content_score, calculate_risk_score(tool_findings))
            last_decision = most_severe([content_decision, tool_decision])

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
    input_findings = _scan_messages(messages) if isinstance(messages, list) else []

    input_risk_score = calculate_risk_score(input_findings)
    input_decision = decide(input_findings, input_risk_score)
    forward_body = raw_body
    enforcement_status = EnforcementStatus.NOT_APPLICABLE

    if input_decision == Decision.SANITIZE:
        context_findings = [f for f in input_findings if f.origin != "input"]
        if context_findings:
            # A SANITIZE verdict influenced by tool/context-message findings
            # isn't something rewriting the latest user message would fix --
            # reported as not applicable rather than sanitizing something
            # that wouldn't address why the decision was made.
            enforcement_status = EnforcementStatus.NOT_APPLICABLE
        else:
            user_texts = [_extract_text(m.get("content")) for m in messages if m.get("role") == "user"]
            latest_user_text = user_texts[-1] if user_texts else ""
            sanitize_result = enforce_sanitize(latest_user_text, input_findings)
            enforcement_status = sanitize_result.enforcement_status
            input_decision = sanitize_result.decision
            input_findings = sanitize_result.findings
            input_risk_score = sanitize_result.risk_score
            if sanitize_result.enforcement_status in (EnforcementStatus.ENFORCED, EnforcementStatus.ESCALATED):
                forward_body = _substitute_latest_user_message(dict(body), sanitize_result.sanitized_text)

    scan_id = str(uuid.uuid4())
    log_scan_event(scan_id, "proxy_input", input_risk_score, input_decision.value, input_findings)

    if input_decision == Decision.BLOCK:
        return _blocked_response(input_findings, input_risk_score, input_decision, stage="input")

    if body.get("stream"):
        # Sanitize enforcement is not yet wired into the streaming path --
        # SANITIZE decisions here still just proceed unmodified, same as
        # before. A real, stated limitation, not a silent gap.
        return StreamingResponse(
            _stream_and_scan(scan_id, raw_body, dict(request.headers)),
            media_type="text/event-stream",
            headers={
                "X-SentinelCore-Input-Decision": input_decision.value,
                "X-SentinelCore-Input-Risk-Score": str(input_risk_score),
            },
        )

    upstream_response = await forward_to_upstream(
        path="/v1/chat/completions",
        method="POST",
        headers=dict(request.headers),
        body=forward_body,
    )

    assistant_text = _extract_assistant_text(upstream_response.content)
    output_findings = _scan_text(assistant_text, origin="output") if assistant_text else []
    output_risk_score = calculate_risk_score(output_findings)
    content_decision = decide(output_findings, output_risk_score)

    # Model-generated tool calls are actions, not prose -- they get the full
    # authorization + argument-scanning pipeline, not just text scanning.
    tool_calls = _extract_tool_calls(upstream_response.content)
    tool_findings, tool_decision = _scan_tool_calls(tool_calls)
    output_findings = output_findings + tool_findings
    output_risk_score = max(output_risk_score, calculate_risk_score(tool_findings))
    output_decision = most_severe([content_decision, tool_decision])

    log_scan_event(
        scan_id,
        "proxy_output",
        output_risk_score,
        output_decision.value,
        output_findings,
        detail=",".join(c["name"] for c in tool_calls) or None,
    )

    if output_decision == Decision.BLOCK:
        return _blocked_response(output_findings, output_risk_score, output_decision, stage="output")

    response_headers = dict(upstream_response.headers)
    response_headers["X-SentinelCore-Input-Decision"] = input_decision.value
    response_headers["X-SentinelCore-Input-Risk-Score"] = str(input_risk_score)
    response_headers["X-SentinelCore-Input-Enforcement-Status"] = enforcement_status.value
    response_headers["X-SentinelCore-Output-Decision"] = output_decision.value
    response_headers["X-SentinelCore-Output-Risk-Score"] = str(output_risk_score)
    response_headers.pop("content-length", None)
    response_headers.pop("Content-Length", None)

    return Response(
        content=upstream_response.content,
        status_code=upstream_response.status_code,
        headers=response_headers,
    )
