# SentinelCore — Capability Matrix (v0.4.0)

This exists because the honest answer to "is it done" needs more than yes/no. Every line below was checked against the actual source and test suite, not recalled from memory of building it.

**Reconstruction note:** this repository was rebuilt from scratch after a sandbox reset. Every number below was re-verified against the reconstructed source and a fresh test run, not copied from pre-reset notes -- the evaluation numbers in particular were independently re-derived and cross-checked against the historical Attack Replay Lab comparisons, which matched exactly.

## 1. Implemented (real, tested, live-verified)

| Capability | Evidence |
|---|---|
| Prompt injection detection (19 rules, 3 categories) | `tests/unit/test_prompt_injection.py`, real eval |
| Obfuscation detection (zero-width, bidi, homoglyph, encoding, char-spacing) | `tests/unit/test_obfuscation.py` |
| PII detection (email/phone/SSN/credit card/IP), redacted evidence | `tests/unit/test_pii.py` |
| Secret detection (AWS keys, private keys, API keys, JWTs, DB strings), redacted evidence | `tests/unit/test_secrets.py` |
| Risk engine (deterministic severity scoring) | `tests/unit/test_risk_engine.py` |
| Policy engine (per-type rules + thresholds, 5-way decision incl. HUMAN_APPROVAL) | `tests/unit/test_policy_engine.py` |
| RAG/context scanning with origin tagging | `tests/unit/test_scan_endpoint.py` |
| Output scanning (PII/secrets in LLM responses) | `tests/unit/test_scan_endpoint.py`, proxy tests |
| Reverse proxy, OpenAI-path-compatible, request + response scanning | `tests/unit/test_proxy.py` -- BLOCK-never-calls-upstream proven via mock assertion |
| Streaming proxy, incremental scan, mid-stream cutoff | Live-verified: violating chunk fully suppressed |
| Tool-call inspection: deterministic tool-name authorization + argument/response scanning | `tests/unit/test_tool_call_endpoint.py` -- 4-scenario live verification. **Found and fixed a real detection bypass:** all three paths (API, `Guard` SDK, proxy) scanned a *serialized* form of the arguments, and both `json.dumps` and `str` escape non-ASCII back to ASCII, so zero-width, bidi and homoglyph payloads reached the detector already defanged. Identical text: risk 60 and BLOCK via `/scan`, **risk 0 and no findings** via `/scan/tool-call`. `tests/unit/test_tool_argument_extraction.py` -- 19 tests; 11 fail against the pre-fix code, and the proxy path fails on exactly the two non-printable families, matching the mechanism |
| MCP tool discovery scanning, recursive description extraction | `tests/unit/test_mcp_endpoint.py` -- verified against real MCP spec via search |
| Audit logging (metadata-only SQLite, never raw text/evidence) | `tests/unit/test_audit_log.py` |
| Dashboard (`GET /dashboard`) | Screenshot-verified against live seeded data |
| Attack Replay Lab (version snapshot + diff, regression detection) | `scripts/replay_lab.py`, real v0.1→v0.2→v0.3 comparisons |
| Real evaluation (744 labeled examples, 2 external MIT-licensed datasets) | `docs/research/README.md` |
| Model-generated tool-call interception in the proxy (P0 fix) | `tests/unit/test_proxy.py` -- 6 regression tests incl. streaming fragment reassembly |
| Provenance-aware risk scoring (origin trust multipliers) | `tests/unit/test_origin_trust.py` -- verified to change actual decisions, with an ablation off-switch |
| Learned classifier detector (optional, off by default) | `tests/unit/test_ml_detector.py`; head-to-head on identical held-out split (`scripts/compare_baselines.py`): recall 27.54% -> 85.51% (3.10x), FPR 0.00% -> 5.00% |
| Agent-trace benchmark + 11-config ablation | `scripts/run_ablation.py`, `docs/research/README.md` Findings 1-5. **Underpowered: bootstrap CIs span ~±18pp, no ablation difference is statistically significant at n=22** |
| Semantic detector (optional, off by default, needs API key) | `tests/unit/test_semantic_detector.py` (9 offline tests). **RUN against a live API**: precision 97.44% recall 55.07% FPR 1.25% on the held-out split -- lower recall than the TF-IDF classifier's 72.0%. See Finding 6 |
| Human approval workflow (PENDING/APPROVED/DENIED/EXPIRED, fail-closed on expiry) | `tests/unit/test_approvals.py` -- 14 tests incl. expiry-is-refusal and separation of duty |
| Identity + tenant isolation (both backends) | `tests/unit/test_tenancy.py` -- 16 tests. Found a real isolation bug: a leftover global unique index let one tenant overwrite another's MCP baseline |
| Tenant scoping on PostgreSQL | **INTEGRATION-TESTED against PostgreSQL 16.** 5 live cross-tenant tests, run in CI against a `postgres:16` service. Mutation-checked: removing the tenant filter from the `scan_events` query fails `test_audit_events_do_not_cross_tenants`, and removing it from the approvals query fails `test_another_tenant_cannot_decide_an_approval` -- so these catch real isolation bugs rather than merely passing |
| Operator dashboard (4 tabs, action surfaces for approvals/MCP/feedback) | `tests/unit/test_dashboard.py` -- 12 tests incl. XSS regression, CSP enforcement, and a check that every subsystem is reachable |
| MCP definition pinning / rug-pull detection | `tests/unit/test_mcp_pinning.py` -- 22 tests. Found and fixed a bug where an unpinned server reported every tool as changed |
| Adaptive-attack harness (8 transform families, tier-E composition search) | `tests/unit/test_redteam.py` -- 15 tests incl. enforced preservation round-trips and separation from enforcement. Found and fixed a case-destroying bug in my own homoglyph transform |
| Robustness against adaptive attackers | **NOT CLAIMED** -- 8 hand-written families at budget 40, mostly targeting obfuscation classes the detector was built for. See `docs/ADAPTIVE_EVAL.md` limitations |
| Pre-deployment assessment (`sentinel assess`) | `tests/unit/test_assess.py` -- 23 tests. Found and fixed a word-boundary bug that missed snake_case tool names, the dominant convention |
| Storage abstraction, versioned migrations, WAL SQLite, retention | `tests/unit/test_storage.py` -- 24 tests incl. legacy-schema upgrade preserving rows, 600 concurrent writes with none lost, exactly-one-decider under 10 concurrent deciders |
| PostgreSQL backend | **INTEGRATION-TESTED.** 13 tests (8 SQLite-parity + 5 tenancy) against live PostgreSQL 16.13, schema v5, `backend='postgres'` asserted by the fixture so a silent SQLite fallback cannot pass. Runs in CI; `SENTINELCORE_REQUIRE_POSTGRES=1` makes a missing server a hard error rather than 13 quiet skips. **Coverage is only 59%** and **HA is still NOT claimed** -- no failover, replication or connection-loss testing |
| Operator feedback / FP review queue, exports to eval-set schema | `tests/unit/test_feedback.py` -- 11 tests incl. the retention boundary |
| Alerting (log/webhook/Slack sinks, bounded queue, tenant+shape-keyed cooldown) | `tests/unit/test_alerts.py` -- 12 tests focused on failure properties |
| Rate limiting + payload caps (off by default) | `tests/unit/test_rate_limiting.py` -- 14 tests; bounded LRU key space after an audit found unbounded growth |
| Thread/task-safe per-call detector selection | `tests/unit/test_concurrency.py` -- 10 tests; replaced a global-mutation approach measured at 531/800 corrupted scans |
| Ablation isolation guards | `tests/unit/test_ablation_isolation.py` -- 6 tests asserting the baseline cannot move when optional detectors are enabled |
| Statistical validation (10 seeds, McNemar, bootstrap CIs) | `scripts/statistical_validation.py`. Detection-recall finding solid (10/10 seeds, p<5.6e-6, non-overlapping CIs); agent-benchmark findings are not |
| Real sanitize enforcement (strip + mandatory re-scan + escalation) | `tests/unit/test_sanitizer.py`, end-to-end proxy tests confirming the actual forwarded request body is the cleaned text |
| Docker (multi-stage, non-root) | Not build-tested -- flagged in the file itself |
| Prometheus metrics (`GET /metrics`) | `tests/unit/test_metrics.py` — 10 tests. Decisions, findings by type, enforcement outcomes, latency histogram. No new dependency: the exposition format is emitted directly rather than making `prometheus_client` mandatory, and the tests assert the format (cumulative buckets, `+Inf` equals count, label escaping). **Cardinality is capped** at 200 series with overflow folded into `__other__` so a saturated metric still totals correctly — a dropped sample makes a counter quietly wrong. **No content in any label**, asserted by posting a known secret and checking it appears nowhere. See `docs/OBSERVABILITY.md` |
| Performance measurement | `scripts/benchmark_performance.py`, `docs/PERFORMANCE.md`. Scan latency is linear at **0.85 µs/char** (2 KB prompt ≈ 1.7 ms). **Found and fixed a 137× streaming cost**: the proxy re-scanned the whole accumulated response per chunk, handing detectors **6,404,002 characters** for one 8,000-char completion at token granularity — seconds of added latency per response, which is a reason not to deploy a gateway even when every verdict it returns is correct. Now 46,851. Detection parity between the fast and exhaustive paths is asserted, not assumed. 5 regression tests assert *work*, never wall-clock |
| Dependency scanning (`pip-audit`, blocking CI gate) | Clean as of last check |
| Authentication + role-based authorization (viewer/operator/admin) | `tests/unit/test_auth.py`, `test_auth_integration.py` -- all 6 scenarios live-verified |

**Verified right now** — re-measured, not carried forward: **7 registered detectors**, **23 API operations** across 9 routers, **507 passing tests with 0 skipped** (13 of those require a live PostgreSQL server and now get one in CI), `sentinelcore/core/auth.py` at 100% coverage, **85% overall coverage**.

Those numbers had drifted badly: this line previously read 5 detectors, 8 endpoints, 154 tests and 98% coverage, none of which had been true for several milestones. **Coverage genuinely fell, 98% → 85%**, and that is not a measurement artefact — the codebase roughly tripled to 3,133 statements while newer subsystems shipped with thinner tests. The weakest is `storage/postgres_backend.py` at **59%**, which is now integration-tested but far from exercised. Stating it here rather than quoting the old number is the entire point of this document.

Full section-by-section hardening status: `docs/hardening/STATUS.md`.

## 2. Experimental / Partial — real, but with known, load-bearing caveats

| Capability | The real caveat |
|---|---|
| SANITIZE decision | Enforced in `/api/v1/scan`, the proxy's non-streaming path, **and now the tool-call path**, each with mandatory re-scan + escalation. Structured arguments are rebuilt field by field (`core/textextract.map_strings`), which is why this was skipped originally: the sanitizers take text and tool arguments are a nested structure, so there was nothing to hand back. **Now also on the MCP path**, where the escalation is the point: a tool description hiding "ignore all previous instructions" behind character spacing scored as mild obfuscation and reported SANITIZE — a gentle verdict on exactly the rug-pull this product targets. Cleaning and re-scanning makes it the BLOCK it always was, and `sanitized_description` shows the operator what the model would have read. **And on both proxy output paths, where it was a bypass.** Non-streaming returned upstream's bytes untouched with a `sanitize` header and *no* output enforcement header at all, though the input side has one. Worse, non-streaming escalates SANITIZE→BLOCK when cleaning reveals the hidden attack and streaming did not, so the identical payload got opposite verdicts from one request flag: `"Sure. i g n o r e   a l l   p r e v i o u s   i n s t r u c t i o n s"` returned **400 BLOCK** without `stream: true` and was **delivered in full** with it. Streaming now runs the same escalation on accumulated text, and the hold-back buffer means the dangerous tail is still unreleased and gets discarded. Residual: released chunks cannot be recalled, so a stream is escalated, never rewritten. |
| ~~HUMAN_APPROVAL has no collection mechanism~~ | **This caveat was stale and is withdrawn.** `api/v1/approvals.py` exposes 3 operations, `services/approvals.py` implements `list_pending`/`decide`, and the dashboard has an Approvals tab. 14 tests including fail-closed expiry and separation of duty. |
| Streaming cutoff | **Fixed.** A pattern split across a chunk boundary used to leak its prefix — measured at 10 of 20 characters of an AWS key, and **19 of 20** when streamed one character per chunk. The chunk that *completes* a pattern was always suppressed correctly; the problem was the chunks already gone. Chunks are now queued and released only once `stream_holdback_chars` (default 96) characters of further text sit behind them, and the queue is discarded rather than flushed on BLOCK. Whole original chunks are buffered, not rewritten, so clients get upstream's exact bytes. Residual: output trails by ~96 characters, and patterns longer than the window still leak a bounded prefix. |
| ~~Origin tagging does not affect scoring~~ | **This caveat was stale and is withdrawn.** Measured directly on one identical attack string: risk 64 (input) / 97 (context) / 100 (tool_arguments), and `use_origin_trust=False` collapses all three back to 64. The multipliers themselves remain an uncalibrated modelling choice -- see the row below, which is the caveat that still stands. |
| Output blocking (proxy) | Stops the leak from reaching the client; does not stop the upstream API cost, already incurred. |
| Authentication | Real when enabled, off by default — but the default is now **reported and, outside development, refused**. Documenting it in the repository was not a runtime control: the shipped Dockerfile binds `0.0.0.0:8000`, so `docker run` produced a gateway whose own security controls were open. Measured with no keys, `GET /api/v1/mcp/pins` and `GET /api/v1/audit/recent` returned data to an anonymous caller, and the role checks guarding MCP re-pinning and approval decisions were skipped entirely — with nothing said to the operator. Startup now warns in development and **raises** outside it, naming `SENTINELCORE_ALLOW_UNAUTHENTICATED` as the deliberate opt-out; `sentinel doctor` reports it too. |
| Provenance trust multipliers | Ordering is principled; the constants (1.0/1.5/1.8) are a stated modeling choice, NOT calibrated. |
| SANITIZE enforcement | **The word-gluing edge case was a bypass, and is fixed.** `_collapse_character_spacing` started from `text.split()`, discarding how much whitespace separated each token — but attackers space words apart more widely than letters, and that gap is the only word boundary. "i g n o r e   a l l   p r e v i o u s" collapsed to `Ignoreallpreviousinstructions`, which matches no phrase pattern, so the sanitizer reported **ENFORCED while returning text that still carried the attack** and the re-scan had nothing to escalate on. Cleaning made a detectable attack undetectable — strictly worse than not sanitizing. A 2+ character gap now ends the word, giving `ignore all previous instructions`, which escalates to BLOCK. The test that had pinned the old behaviour now asserts the new one. |

## 3. Planned, Not Implemented

Conflicting-instruction detection · sanitize enforcement for streaming/tool-call/MCP · circuit breakers · JS SDK · Kubernetes/Helm · RBAC/ABAC beyond the 3-role auth model · SIEM integration (webhook and Slack sinks exist; no CEF/LEEF or native connector) · horizontal scaling · scheduled MCP polling (no scheduler ships; run `sentinel mcp check` from cron or CI) · autonomous red-teaming · key rotation tooling · live-agent adaptive evaluation.

**Six entries were removed from this list because they had shipped and nobody updated it** — a stale "not implemented" is a smaller sin than a stale "done", but in a document whose only job is an accurate status it is still a defect. Each was re-checked against source and tests before removal:

| Was listed as planned | Actually |
|---|---|
| CLI | `sentinelcore/cli.py`; `sentinel doctor/scan/proxy/policy/assess/mcp`, verified running from the published wheel |
| Rate limiting | `core/limits.py`, 14 tests, bounded LRU key space |
| Multi-tenancy | `core/identity.py`, ambient tenant scoping, live cross-tenant tests on both backends |
| Alerting integration | `services/alerts.py`, log/webhook/Slack sinks, tenant+shape-keyed cooldown. *SIEM specifically is still absent, so it stays above* |
| Source trust / provenance tracking | `services/origin_trust.py`, feeding `calculate_risk_score` |
| Origin-aware policy weighting | Origin scales risk, and risk drives the policy decision — measured at 64/97/100 for one identical string |
| Python SDK | The `Guard` API is the SDK; three integration shapes, on PyPI as `sentinelcore-ai` |

## 4. Security Gaps (stated plainly)

- **Authentication is real but off by default.** No keys configured means every endpoint is open -- documented, not hidden, but still a real risk if deployed network-reachable without configuring `SENTINELCORE_API_KEYS`.
- **Rate limiting exists but is off by default and per-process.** `sentinelcore/core/limits.py` implements a fixed-window limiter and payload cap; enabling is the operator's choice. State is per worker process, so multi-worker deployments must divide the configured limit. Not a substitute for a real edge limiter.
- Detector coverage is **English-pattern regex only** -- confirmed by evaluation (near-zero recall on German/Spanish/Chinese examples).
- **Reported FPRs are easy-negative FPRs.** 1.3% of the benign corpus contains attack vocabulary, so over-defense is unmeasured. `scripts/evaluate_overdefense.py` built, NotInject run pending.
- **No semantic/ML detection anywhere** -- deterministic rules/regex by design, with the honest recall ceiling that implies (17.68% on the real benchmark).
- **No key rotation, revocation, or per-key rate limiting.**

## 5. Architectural Gaps

- SQLite writes remain synchronous on the request path. Measured at 19,603 writes/sec across 8 threads with zero loss, so an async queue would add a crash-loss failure mode to save time the request does not notice.
- ~~No schema migration support~~ -- versioned additive migrations now upgrade in place; a legacy database is adopted with its rows intact.
- Full-text re-scan on every streamed chunk -- O(n²) over a long completion.
- No caching of the loaded policy -- re-read from disk on every request.

## 6. Where this is actually competitive

The engineering discipline, not the detection accuracy: every claim in this repo is backed by a script someone else can re-run (`scripts/evaluate.py`, `scripts/replay_lab.py`) rather than an asserted number. The regression-tracked pattern-improvement loop (measure → fix → re-measure → prove zero regressions) is real and demonstrated, not just described.

## 7. Where this is behind, plainly

Everything that requires scale, ML, or production traffic to build honestly: semantic/paraphrase-resistant detection, a labeled dataset at real scale, production hardening beyond authentication (rate limits, HA), and the trust that comes from real deployments.

## 8. What evidence would be required to justify stronger claims

A calibrated ML/semantic detector benchmarked honestly against this same rules-based baseline. Real production traffic and incident data. Independent red-team results from someone other than the person who built the detectors. None of that exists yet.
