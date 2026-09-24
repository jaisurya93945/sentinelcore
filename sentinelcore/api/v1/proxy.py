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

from sentinelcore.core.config import settings
from sentinelcore.core.auth import Role, require_role
from sentinelcore.detectors.registry import get_registered_detectors
from sentinelcore.models.finding import Decision, EnforcementStatus, Finding
from sentinelcore.services.audit_log import log_scan_event
from sentinelcore.services.policy_engine import decide, most_severe
from sentinelcore.services.proxy import forward_to_upstream, stream_lines_from_upstream
from sentinelcore.services.risk_engine import calculate_risk_score
from sentinelcore.services.sanitizer import enforce_sanitize
from sentinelcore.services.tool_policy import authorize_tool
from sentinelcore.core.textextract import extract_scannable_text
from sentinelcore.core.metrics import record_scan

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

        # NOT str(): repr escapes non-printables, so zero-width and bidi
        # payloads were invisible here. See sentinelcore/core/textextract.py.
        arg_findings = _scan_text(extract_scannable_text(call["arguments"]),
                                  origin=f"tool_arguments:{name}")
        all_findings.extend(arg_findings)
        decisions.append(decide(arg_findings, calculate_risk_score(arg_findings)))

    return all_findings, most_severe(decisions)


def _substitute_assistant_content(raw: bytes, sanitized_text: str) -> bytes:
    """Rewrites the assistant message content in an upstream response.

    The response-side counterpart to _substitute_latest_user_message, and it
    did not exist -- which is why the output path could compute a SANITIZE
    decision and then return upstream_response.content untouched. Enforcement
    that does not modify the bytes the client receives is cosmetic.

    Returns the original bytes unchanged if the shape is not what we expect,
    so an unfamiliar response is passed through rather than mangled. The
    caller must therefore verify the substitution took, and does.
    """
    try:
        body = json.loads(raw)
        choices = body.get("choices") or []
        for choice in choices:
            msg = choice.get("message")
            if isinstance(msg, dict) and isinstance(msg.get("content"), str):
                msg["content"] = sanitized_text
                return json.dumps(body).encode("utf-8")
    except (json.JSONDecodeError, AttributeError, TypeError):
        pass
    return raw


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
      verified by test and by a live run, not assumed.

      A pattern split across a chunk boundary used to leak its prefix:
      the first chunk matches nothing on its own, so it went out before
      the second completed the pattern. Measured, an AWS key streamed as
      "...AKIAIOSFOD" + "NN7EXAMPLE" delivered 10 of its 20 characters;
      streamed one character per chunk it delivered 19 of 20.

      This docstring used to say the leak was unfixable -- "scanning
      faster doesn't fix this; it's a property of chunk boundaries".
      Scanning was the wrong lever. The fix is to RELEASE later, not to
      scan sooner: chunks are now queued and held until at least
      settings.stream_holdback_chars characters of further text have
      arrived behind them, and the queue is DISCARDED rather than
      flushed on BLOCK. Whole original chunks are buffered rather than
      rewritten, so clients still receive upstream's exact bytes and
      tool-call fragments get the same protection as content.

      The residual cost is latency, not exposure: output trails upstream
      by roughly that many characters. Patterns longer than the window
      (JWTs, private key bodies) still leak a bounded prefix -- raise the
      setting to trade latency for exposure, or set 0 to restore the old
      immediate-release behaviour.
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

    # HOLD-BACK BUFFER. Chunks are scanned immediately but RELEASED late,
    # keeping at least settings.stream_holdback_chars characters of text
    # unsent. Whole original chunks are queued rather than rewritten, so
    # the bytes a client receives are byte-for-byte what upstream sent --
    # no reshaped deltas, and tool-call fragments are covered by the same
    # mechanism as content. On BLOCK the queue is DISCARDED, which is the
    # entire point: it holds the prefix of the pattern that just matched.
    last_content_findings: list[Finding] = []
    pending: list[tuple[str, int]] = []   # (raw data_str, characters of text it carries)
    buffered_chars = 0
    holdback = max(0, settings.stream_holdback_chars)
    window = max(0, settings.stream_scan_window_chars)
    # Capped at holdback so text can never be released before it has been
    # scanned: release requires `holdback` characters queued behind a
    # chunk, and a scan happens at least every `stride` characters.
    stride = min(max(0, settings.stream_scan_stride_chars), holdback) if holdback else 0
    scanned_upto = 0

    async for line in stream_lines_from_upstream(
        path="/v1/chat/completions", method="POST", headers=headers, body=raw_body
    ):
        if not line.startswith("data: "):
            continue
        data_str = line[len("data: ") :]

        if data_str.strip() == "[DONE]":
            # BACKSTOP. Windowed scanning can only see patterns that fit the
            # window, so the complete response is scanned once here, before
            # anything still held is released. This is what bounds the cost
            # of narrowing the window: something longer than it is caught
            # late rather than never, and "late" still precedes the release
            # of the hold-back tail.
            if accumulated_text and (scanned_upto < len(accumulated_text) or
                                     (window and len(accumulated_text) > window)):
                final_findings = _scan_text(accumulated_text, origin="output")
                final_score = calculate_risk_score(final_findings)
                if decide(final_findings, final_score) == Decision.BLOCK:
                    last_findings, last_risk_score = final_findings, final_score
                    last_decision = Decision.BLOCK
                    pending.clear()
                    yield 'data: {"choices":[{"delta":{},"finish_reason":"content_filter","index":0}]}\n\n'
                    yield "data: [DONE]\n\n"
                    break

            for ds, _ in pending:
                yield f"data: {ds}\n\n"
            pending.clear()
            yield "data: [DONE]\n\n"
            break

        delta_content = ""
        # Re-bound every iteration on purpose. Scoped to the try, it would
        # retain the PREVIOUS chunk's value whenever parsing failed, and the
        # hold-back accounting below would then charge this chunk with
        # another one's characters -- a silent mis-count, which is worse
        # than the NameError it replaced.
        delta: dict = {}
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

            # Scan on accumulated NEW text, not on every chunk, and only
            # the tail window plus that new text -- never the whole
            # response again. This is what removes the chunk-count term
            # from the cost; see settings.stream_scan_stride_chars.
            unscanned = len(accumulated_text) - scanned_upto
            due = (not stride) or unscanned >= stride or bool(accumulated_tool_calls)

            if due and accumulated_text:
                if window and len(accumulated_text) > window + unscanned:
                    scan_target = accumulated_text[-(window + unscanned):]
                else:
                    scan_target = accumulated_text
                content_findings = _scan_text(scan_target, origin="output")
                scanned_upto = len(accumulated_text)
                last_content_findings = content_findings
            else:
                # Nothing new enough to re-examine; keep the previous
                # verdict rather than silently reporting "clean".
                content_findings = last_content_findings
            content_score = calculate_risk_score(content_findings)
            content_decision = decide(content_findings, content_score)

            named_calls = [c for c in accumulated_tool_calls.values() if c["name"]]
            tool_findings, tool_decision = _scan_tool_calls(named_calls)

            last_findings = content_findings + tool_findings
            last_risk_score = max(content_score, calculate_risk_score(tool_findings))
            last_decision = most_severe([content_decision, tool_decision])

            # SANITIZE HAS TO ESCALATE HERE TOO, or `stream: true` is a
            # bypass of the whole output pipeline.
            #
            # The non-streaming path sanitizes, re-scans, and escalates
            # when cleaning reveals an attack the obfuscation was hiding.
            # This path only ever acted on BLOCK, so the identical payload
            # got opposite verdicts depending on one request flag.
            # Measured: "Sure. i g n o r e   a l l   p r e v i o u s
            # i n s t r u c t i o n s" returned 400 BLOCK without the flag
            # and was delivered in full with it.
            #
            # Released chunks cannot be recalled, so rewriting the stream
            # is not on offer -- but the ESCALATION is, and that is the
            # half that matters. It runs on accumulated text, so the
            # verdict is identical to the non-streaming one, and the
            # hold-back buffer means the dangerous tail is still in
            # `pending` and gets discarded with it.
            if last_decision == Decision.SANITIZE and accumulated_text:
                escalated = enforce_sanitize(accumulated_text, content_findings)
                if escalated.decision == Decision.BLOCK:
                    last_decision = Decision.BLOCK
                    last_findings = escalated.findings + tool_findings
                    last_risk_score = max(escalated.risk_score,
                                          calculate_risk_score(tool_findings))

            if last_decision == Decision.BLOCK:
                # Discard, do not flush: these chunks carry the beginning of
                # the very pattern that just matched. Flushing them here
                # would deliver the leak this buffer exists to prevent.
                pending.clear()
                yield 'data: {"choices":[{"delta":{},"finish_reason":"content_filter","index":0}]}\n\n'
                yield "data: [DONE]\n\n"
                break

        # Queue rather than emit. A chunk leaves only once enough further
        # text has arrived behind it that any pattern it might start would
        # already have been scanned.
        arg_chars = sum(len((tc.get("function") or {}).get("arguments") or "")
                        for tc in (delta.get("tool_calls") or []))
        pending.append((data_str, len(delta_content) + arg_chars))
        buffered_chars += len(delta_content) + arg_chars
        while pending and buffered_chars - pending[0][1] >= holdback:
            ds, n = pending.pop(0)
            buffered_chars -= n
            yield f"data: {ds}\n\n"

    record_scan("proxy_output_stream", last_decision.value, findings=last_findings, stage="output_stream")
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
    record_scan("proxy_input", input_decision.value, findings=input_findings,
                enforcement_status=enforcement_status.value, stage="input")
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

    # SANITIZE on the OUTPUT path used to fall straight through to the
    # return below, handing the client upstream's original bytes while the
    # X-SentinelCore-Output-Decision header said "sanitize" -- and there was
    # no output enforcement-status header at all, though the INPUT side has
    # one. So the response announced an action it had not taken, and offered
    # the client no way to notice. Measured before this fix: a response with
    # character-spacing evasion returned decision=sanitize, risk 36, body
    # byte-identical to upstream.
    output_enforcement = EnforcementStatus.NOT_APPLICABLE
    output_body = upstream_response.content

    if output_decision == Decision.SANITIZE and assistant_text:
        san = enforce_sanitize(assistant_text, output_findings)
        output_enforcement = san.enforcement_status
        output_findings = san.findings
        output_risk_score = max(san.risk_score, calculate_risk_score(tool_findings))
        output_decision = most_severe([san.decision, tool_decision])
        for f in output_findings:
            if not f.origin:
                f.origin = "output"

        if san.enforcement_status in (EnforcementStatus.ENFORCED, EnforcementStatus.ESCALATED):
            rewritten = _substitute_assistant_content(upstream_response.content, san.sanitized_text)
            if rewritten is upstream_response.content:
                # The shape was unfamiliar, so nothing was rewritten. Saying
                # ENFORCED here would be the exact lie this block removes.
                output_enforcement = EnforcementStatus.NOT_IMPLEMENTED
            else:
                output_body = rewritten

    # Logged AFTER enforcement, not before. Sanitizing can escalate
    # SANITIZE to BLOCK, and an audit trail that records the decision the
    # engine first reached rather than the one it acted on is exactly the
    # kind of record that is worse than none -- an incident review would
    # read "sanitize" for a request that was refused.
    record_scan("proxy_output", output_decision.value, findings=output_findings,
                enforcement_status=output_enforcement.value, stage="output")
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
    # Always emitted, including NOT_APPLICABLE. Its absence was what let a
    # SANITIZE decision look enforced, and a header that appears only
    # sometimes cannot be relied on by a client.
    response_headers["X-SentinelCore-Output-Enforcement-Status"] = output_enforcement.value
    response_headers.pop("content-length", None)
    response_headers.pop("Content-Length", None)

    return Response(
        content=output_body,
        status_code=upstream_response.status_code,
        headers=response_headers,
    )
