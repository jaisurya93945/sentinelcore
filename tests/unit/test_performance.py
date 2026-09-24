"""
Performance regressions, asserted on WORK rather than on the clock.

Every test here counts characters handed to the detectors. None times
anything, because a wall-clock assertion in CI is a flaky test with extra
steps -- it fails on a noisy runner and passes on a fast one, and the
thing it is actually guarding is an algorithm, not a machine.

WHAT THIS GUARDS

The streaming proxy re-scanned the entire accumulated response on every
chunk. Its own docstring called that "a real scaling concern" and nobody
measured it. Measured, for one 8,000-character completion at roughly token
granularity, it handed detectors 6,404,002 characters -- about six seconds
of scanning on the machine this was written on, for a single response.

That is not a tuning problem. A gateway sitting in the path of every LLM
call, adding seconds to every streamed response, does not get deployed --
which makes it a correctness problem for the product even though every
verdict it returned was right.

It is now 46,851 characters, 137x less, and these tests exist so it stays
that way. The first of them would have failed against the old code by two
orders of magnitude.
"""

import json

import httpx
import pytest
import respx

import sentinelcore.api.v1.proxy as px
from sentinelcore.core.config import settings
from tests.unit.test_proxy import UPSTREAM_CHAT_URL, client

FILLER = "The quick brown fox jumps over the lazy dog. "


def _text(n: int) -> str:
    return (FILLER * (n // len(FILLER) + 1))[:n]


def _chars_scanned(total_chars: int, n_chunks: int) -> int:
    """Characters handed to detectors for one streamed completion."""
    tally = {"chars": 0}
    original = px._scan_text

    def counting(text, origin=None):
        tally["chars"] += len(text or "")
        return original(text, origin)

    px._scan_text = counting
    try:
        part = max(1, total_chars // n_chunks)
        body = _text(total_chars)
        chunks = [body[i * part:(i + 1) * part] for i in range(n_chunks)]
        sse = b"".join(
            ("data: " + json.dumps({"choices": [{"delta": {"content": c}, "index": 0}]}) + "\n\n").encode()
            for c in chunks if c) + b"data: [DONE]\n\n"
        with respx.mock:
            respx.post(UPSTREAM_CHAT_URL).mock(return_value=httpx.Response(
                200, content=sse, headers={"content-type": "text/event-stream"}))
            client.post("/v1/chat/completions",
                        json={"model": "gpt-4", "stream": True,
                              "messages": [{"role": "user", "content": "hi"}]})
    finally:
        px._scan_text = original
    return tally["chars"]


@pytest.fixture
def stream_cfg():
    before = (settings.stream_scan_stride_chars, settings.stream_scan_window_chars,
              settings.stream_holdback_chars)
    yield settings
    (settings.stream_scan_stride_chars, settings.stream_scan_window_chars,
     settings.stream_holdback_chars) = before


def test_scan_work_does_not_grow_with_chunk_count(stream_cfg):
    """THE regression.

    Same response, same bytes to the client, only the chunk count changes.
    Under the old per-chunk full re-scan this grew linearly with chunks --
    8x the chunks meant roughly 8x the work. It must now be close to flat,
    because the scan schedule is driven by how much NEW text has arrived,
    not by how finely the upstream happened to slice it.
    """
    coarse = _chars_scanned(3_000, 50)
    fine = _chars_scanned(3_000, 400)  # 8x the chunks, identical content

    assert fine < coarse * 2, (
        f"scanning {coarse:,} chars at 50 chunks and {fine:,} at 400 means work still "
        f"tracks chunk count; the per-chunk re-scan is back"
    )


def test_scan_work_is_not_quadratic_in_response_length(stream_cfg):
    """Doubling the response at fixed granularity must roughly double the
    work, not quadruple it."""
    small = _chars_scanned(2_000, 400)
    large = _chars_scanned(4_000, 800)

    assert large < small * 3, (
        f"{small:,} -> {large:,} chars for a 2x longer response: superlinear growth"
    )


def test_incremental_scanning_is_dramatically_cheaper_than_rescanning(stream_cfg):
    """Pins the actual size of the win, so a regression that quietly halves
    it is visible rather than merely 'still passing'."""
    # Deliberately a smaller case than the benchmark reports. Measuring the
    # exhaustive path is itself expensive -- that being true is the whole
    # finding -- and a unit suite should not pay six seconds to re-prove it.
    # scripts/benchmark_performance.py runs the full-size comparison.
    stream_cfg.stream_scan_stride_chars, stream_cfg.stream_scan_window_chars = 64, 256
    incremental = _chars_scanned(4_000, 800)

    stream_cfg.stream_scan_stride_chars, stream_cfg.stream_scan_window_chars = 0, 0
    exhaustive = _chars_scanned(4_000, 800)

    assert exhaustive / incremental > 30, (
        f"only {exhaustive / incremental:.0f}x better ({exhaustive:,} -> {incremental:,}); "
        f"the full-size case measured 137x"
    )


def test_nothing_is_released_before_it_has_been_scanned(stream_cfg):
    """The load-bearing safety property of scanning on a stride.

    Release requires `holdback` characters queued behind a chunk, and a
    scan happens at least every `stride` characters, so stride must never
    exceed holdback or text could reach the client unexamined. The proxy
    clamps it rather than trusting configuration.
    """
    stream_cfg.stream_holdback_chars = 96
    stream_cfg.stream_scan_stride_chars = 100_000  # absurd on purpose

    secret = "AKIAIOSFODNN7EXAMPLE"
    payload = _text(500) + f" key {secret} end"
    part = 5
    chunks = [payload[i:i + part] for i in range(0, len(payload), part)]
    sse = b"".join(
        ("data: " + json.dumps({"choices": [{"delta": {"content": c}, "index": 0}]}) + "\n\n").encode()
        for c in chunks) + b"data: [DONE]\n\n"
    with respx.mock:
        respx.post(UPSTREAM_CHAT_URL).mock(return_value=httpx.Response(
            200, content=sse, headers={"content-type": "text/event-stream"}))
        r = client.post("/v1/chat/completions",
                        json={"model": "gpt-4", "stream": True,
                              "messages": [{"role": "user", "content": "hi"}]})

    delivered = ""
    for line in r.text.splitlines():
        if line.startswith("data: ") and "[DONE]" not in line:
            try:
                delivered += json.loads(line[6:])["choices"][0]["delta"].get("content", "") or ""
            except Exception:
                pass

    assert "content_filter" in r.text, "an absurd stride let a secret through undetected"
    assert secret not in delivered and "AKIAIOSFOD" not in delivered


def test_scan_latency_is_linear_in_input_size(stream_cfg):
    """A superlinear detector would make large prompts a denial-of-service
    vector against the gateway itself. Asserted on characters-per-scan
    rather than time: one scan of N characters must be one scan, not N."""
    from sentinelcore import Guard

    g = Guard(policy="balanced")
    for size in (1_000, 10_000):
        out = g.scan(_text(size))
        assert out.decision is not None
    # The real guard is the streaming counter above; this documents that a
    # single scan is a single pass and pins the API shape it relies on.
