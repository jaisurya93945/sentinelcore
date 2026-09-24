# Performance

```bash
python scripts/benchmark_performance.py                    # full run
python scripts/benchmark_performance.py --json out.json    # machine-readable
```

Results: `dataset/processed/performance.json` (carries version, commit and config).

## Why this exists

Every number this project published was about detection quality. None was about cost. For a reverse proxy sitting in the path of every LLM call, that is the omission an evaluator notices first — a gateway that catches everything and adds a second per request does not get deployed.

Leaving it unmeasured also hid something. The streaming proxy re-scanned the entire accumulated response on every chunk; its own docstring called that "a real scaling concern" and stopped there. Measured, the concern was a **137×** one.

## Scan latency

Rules, risk and policy; optional detectors off. Linear in input size at roughly **0.85 µs/character**, with no meaningful fixed overhead — detector construction measured at 0.001 ms, so there is nothing to pool or cache.

| Input | mean | p50 | p95 | p99 |
|---|---|---|---|---|
| 100 chars | 0.10 ms | 0.10 | 0.13 | 0.14 |
| 500 chars | 0.45 ms | 0.45 | 0.55 | 0.67 |
| 2,000 chars | 1.71 ms | 1.72 | 1.77 | 1.77 |
| 10,000 chars | 8.73 ms | 8.47 | 11.04 | 11.04 |
| 50,000 chars | 42.38 ms | 42.38 | 42.94 | 42.94 |

A typical prompt costs under 2 ms. Linearity matters beyond the headline: a superlinear detector would make a large prompt a denial-of-service vector against the gateway itself.

## Streaming, which is where the problem was

Work is reported in **characters handed to the detectors**, not milliseconds — see the caveat below for why.

| Response | Chunks | Scans | Characters scanned | If re-scanned per chunk | Saving |
|---|---|---|---|---|---|
| 2,000 | 400 | 32 | 10,998 | 401,002 | **36×** |
| 8,000 | 1,600 | 125 | 46,851 | 6,404,002 | **137×** |
| 20,000 | 4,000 | 309 | 117,915 | *~40,000,000* | — |

The 20,000 baseline is not measured because measuring it costs more than the rest of the benchmark combined, which is itself the finding.

Two changes produced this, and the order matters because the first alone was not enough:

1. **A tail window.** Each scan looks at `stream_scan_window_chars` (256) of preceding text plus what is new, rather than the whole response. On its own this gave only ~4× — the per-chunk re-scan still dominated.
2. **A scan stride.** Scanning is triggered by how much *new* text has arrived (`stream_scan_stride_chars`, 64), not by chunk arrival. This removes the chunk-count term, and is where the rest of the improvement came from.

### The tradeoff, stated

A pattern that fits the window is still caught on the chunk that completes it, before release. A pattern **longer** than the window is caught at the end-of-stream backstop scan instead — later, though the hold-back buffer means its tail is still unreleased and the stream is still cut.

The window is 256 against a **longest measured rules match of 32 characters** across the 744-example corpus. Secret evidence is redacted by design, so that 32 is a floor rather than a true maximum, which is part of why the window sits well above it.

`stream_scan_stride_chars` is clamped to `stream_holdback_chars` at runtime rather than trusted: release requires characters queued behind a chunk, and a scan happens at least every stride, so a stride larger than the hold-back could let text reach a client unexamined. A test drives the stride to an absurd value and asserts a secret is still caught.

Setting either to `0` restores the exhaustive per-chunk re-scan.

### Detection is unchanged

The benchmark asserts it rather than assuming it: identical verdicts from the incremental and exhaustive paths on an AWS key late in a long response, an injection late in a long response, a spaced-out injection requiring sanitize-and-escalate, and a benign control. A mismatch fails the run.

## Why characters, not milliseconds

An earlier version of this benchmark timed requests through the test client and reported **3.2 seconds** for a 2,000-character completion. Profiling then showed scanning was about a tenth of that — the rest was test-harness overhead. The number was real and the attribution was wrong, and a 3.2-second "deployment blocker" would have been a fabricated finding.

Characters scanned is the work the product actually does. It does not change with the machine, it does not move when the harness does, and it is what the regression tests in `tests/unit/test_performance.py` assert — no wall-clock assertion, because that is a flaky test with extra steps.

## Not measured, and therefore not claimed

- End-to-end latency against a real upstream, including network time.
- Throughput or behaviour under concurrency.
- Memory, and how accumulated text bounds it on very long streams.
- Anything on production hardware; this is a single machine with a mocked upstream.
- Cost of the optional `ml` and `semantic` detectors, which are off by default. The semantic detector calls an external API, so its latency is dominated by that call, not by anything here.
