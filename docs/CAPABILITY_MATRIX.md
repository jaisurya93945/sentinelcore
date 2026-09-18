# SentinelCore — Capability Matrix (v0.3.0)

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
| Tool-call inspection: deterministic tool-name authorization + argument/response scanning | `tests/unit/test_tool_call_endpoint.py` -- 4-scenario live verification |
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
| Identity + tenant isolation (SQLite) | `tests/unit/test_tenancy.py` -- 16 tests. Found a real isolation bug: a leftover global unique index let one tenant overwrite another's MCP baseline |
| Tenant scoping on PostgreSQL | **NOT IMPLEMENTED** -- do not run multi-tenant on the PostgreSQL backend |
| Operator dashboard (4 tabs, action surfaces for approvals/MCP/feedback) | `tests/unit/test_dashboard.py` -- 12 tests incl. XSS regression, CSP enforcement, and a check that every subsystem is reachable |
| MCP definition pinning / rug-pull detection | `tests/unit/test_mcp_pinning.py` -- 22 tests. Found and fixed a bug where an unpinned server reported every tool as changed |
| Pre-deployment assessment (`sentinel assess`) | `tests/unit/test_assess.py` -- 23 tests. Found and fixed a word-boundary bug that missed snake_case tool names, the dominant convention |
| Storage abstraction, versioned migrations, WAL SQLite, retention | `tests/unit/test_storage.py` -- 24 tests incl. legacy-schema upgrade preserving rows, 600 concurrent writes with none lost, exactly-one-decider under 10 concurrent deciders |
| PostgreSQL backend | **IMPLEMENTED, NOT INTEGRATION-TESTED** -- 8 tests skip without `SENTINELCORE_TEST_POSTGRES_URL`; no server was reachable in the dev environment. HA is NOT claimed |
| Operator feedback / FP review queue, exports to eval-set schema | `tests/unit/test_feedback.py` -- 11 tests incl. the retention boundary |
| Alerting (log/webhook/Slack sinks, bounded queue, shape-keyed cooldown) | `tests/unit/test_alerts.py` -- 12 tests focused on failure properties |
| Rate limiting + payload caps (off by default) | `tests/unit/test_rate_limiting.py` -- 14 tests; bounded LRU key space after an audit found unbounded growth |
| Thread/task-safe per-call detector selection | `tests/unit/test_concurrency.py` -- 10 tests; replaced a global-mutation approach measured at 531/800 corrupted scans |
| Ablation isolation guards | `tests/unit/test_ablation_isolation.py` -- 6 tests asserting the baseline cannot move when optional detectors are enabled |
| Statistical validation (10 seeds, McNemar, bootstrap CIs) | `scripts/statistical_validation.py`. Detection-recall finding solid (10/10 seeds, p<5.6e-6, non-overlapping CIs); agent-benchmark findings are not |
| Real sanitize enforcement (strip + mandatory re-scan + escalation) | `tests/unit/test_sanitizer.py`, end-to-end proxy tests confirming the actual forwarded request body is the cleaned text |
| Docker (multi-stage, non-root) | Not build-tested -- flagged in the file itself |
| Dependency scanning (`pip-audit`, blocking CI gate) | Clean as of last check |
| Authentication + role-based authorization (viewer/operator/admin) | `tests/unit/test_auth.py`, `test_auth_integration.py` -- all 6 scenarios live-verified |

**Verified right now:** 5 registered detectors, 8 API endpoints, 154 passing tests, `sentinelcore/core/auth.py` at 100% coverage, 98% overall coverage. Full section-by-section hardening status: `docs/hardening/STATUS.md`.

## 2. Experimental / Partial — real, but with known, load-bearing caveats

| Capability | The real caveat |
|---|---|
| SANITIZE decision | Enforced in `/api/v1/scan` and the proxy's non-streaming path with mandatory re-scan + escalation. Not yet wired into streaming/tool-call/MCP paths. |
| HUMAN_APPROVAL decision | Returned correctly; no mechanism exists to collect an actual approval. |
| Streaming cutoff | A trigger pattern split exactly across a chunk boundary can partially leak before detection completes. |
| Origin tagging | Tracked and returned, but doesn't yet affect scoring or policy. |
| Output blocking (proxy) | Stops the leak from reaching the client; does not stop the upstream API cost, already incurred. |
| Authentication | Real when enabled, but off by default -- a documented risk if network-reachable without configuring it. |
| Provenance trust multipliers | Ordering is principled; the constants (1.0/1.5/1.8) are a stated modeling choice, NOT calibrated. |
| SANITIZE enforcement | Real for the finding types with a defined transform; a multi-word character-spacing collapse can under-represent danger by gluing words together (documented edge case, not hidden). |

## 3. Planned, Not Implemented

Conflicting-instruction detection · source trust/provenance tracking · sanitize enforcement for streaming/tool-call/MCP · origin-aware policy weighting · rate limiting/circuit breakers · Python/JS SDKs · CLI · Kubernetes/Helm · RBAC/ABAC beyond the 3-role auth model · SIEM/alerting integration · multi-tenancy · horizontal scaling · autonomous red-teaming · key rotation tooling.

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
