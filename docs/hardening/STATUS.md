# Hardening Status

Section-by-section status against `docs/hardening/MASTER_PROMPT.md`. Updated as work happens, not written once and left stale.

Status values: **DONE** (implemented and tested) · **PARTIAL** (real, with a stated gap) · **DECLINED** (explicit reasoning given, not silently skipped) · **NOT YET ATTEMPTED** (real candidate, hasn't been picked up).

| # | Section | Status | Notes |
|---|---|---|---|
| 1 | Project context | N/A | Context-setting, not a task |
| 2 | Authenticity rule | ONGOING | A standing principle this whole project already runs on |
| 3 | Freeze and audit | DONE | Performed before v0.3.0; see `docs/CAPABILITY_MATRIX.md` |
| 4 | Claims must be verified | DONE | `docs/CAPABILITY_MATRIX.md` classifies every capability |
| 5 | **Authentication** | **DONE** | `app/core/auth.py`, off by default, tested end-to-end incl. live demo |
| 6 | **Authorization** | **DONE** | 3 roles (viewer/operator/admin), collapsed from the spec's 5 — reasoning stated in `auth.py`'s own docstring |
| 7 | Rate limiting | **PARTIAL — real, off by default** | `app/core/limits.py` + middleware: fixed-window counter keyed by API key (IP fallback), plus a `Content-Length` payload cap checked before the body is read. 14 tests. Stated limits: fixed window permits 2x nominal across a boundary, state is PER WORKER PROCESS not per deployment (no shared store), IP is a weak identity. Not a WAF |
| 8 | Reverse proxy hardening | PARTIAL | Timeout config exists and is enforced. Fail-open/fail-closed behavior is currently **undefined** — detector exceptions are unhandled and would crash the request with a raw 500. Circuit breakers, retry logic: not implemented |
| 9 | Streaming security | PARTIAL | SSE parsing, mid-stream cutoff, chunk-boundary leak limitation: done and documented. UTF-8 mid-character boundaries: not explicitly tested. Latency/memory/CPU: not measured |
| 10 | Input security | DONE | Existing, continuously refined via real evaluation |
| 11 | RAG security | PARTIAL | Indirect injection scanning done. Provenance/trust-level distinctions beyond `origin`: not implemented |
| 12 | Agent security | PARTIAL | Tool-call inspection done. Cumulative risk across a session: not implemented (no session concept exists) |
| 13 | Multi-step agent security | NOT IMPLEMENTED | No action-history or tool-chain tracking exists at all |
| 14 | MCP security | PARTIAL | Static tool-discovery scanning done. A live relay between an actual MCP client and server: not implemented |
| 15 | MCP authorization (OAuth) | DECLINED | Cannot be implemented responsibly without a real MCP server/OAuth provider to test against |
| 16 | Output security | DONE | Existing |
| 17 | Real sanitization | **PARTIAL — real, not fabricated** | `app/services/sanitizer.py`: strip/normalize + mandatory re-scan + escalation, actually wired into `/api/v1/scan` and the proxy's non-streaming path with `decision`/`enforcement_status` genuinely separated. Verified end-to-end (the forwarded proxy request body is confirmed to contain the cleaned text). Not yet wired into streaming, tool-call, or MCP paths — stated scope limit, not a hidden one. One documented edge case: multi-word character-spacing collapse can glue words together in a way that under-represents danger on re-scan. |
| 18 | Risk engine review | DONE | Already deterministic, explainable, testable |
| 19 | Policy engine review | PARTIAL | Deterministic/testable/explainable: yes. Versionable, user/tenant dimensions: not implemented (no identity system to key on yet) |
| 20 | Audit security | PARTIAL | Core fields recorded. Pagination, filtering, retention, rotation, export: not implemented |
| 21 | Database maturity | NOT YET ATTEMPTED | Indexes are cheap and real; migration strategy needs a decision |
| 22 | Observability | PARTIAL | Dashboard shows decision counts and a live timeline. Volume/latency trends over time: not implemented |
| 23 | Multi-tenancy | DECLINED, per the doc's own instruction | "If full multi-tenancy is not appropriate... document it explicitly rather than creating unsafe partial isolation" — followed literally |
| 24 | Secret management | PARTIAL | Env-var config, no secrets in source/git confirmed. No rotation tooling |
| 25 | Supply-chain security | PARTIAL | Dependency scanning (`pip-audit`) real and blocking in CI. SBOM, container scanning, signed artifacts: not implemented |
| 26 | Container security | PARTIAL | Non-root, multi-stage, minimal base image: done. Read-only filesystem, dropped capabilities: not added. Still not build-tested |
| 27 | API security / fuzzing | NOT YET ATTEMPTED | Real, achievable candidate |
| 28 | Real provider validation | **DONE — executed against a live OpenAI API** | `api.openai.com` is blocked in the dev sandbox (verified: `x-deny-reason: host_not_allowed`), so this cannot run here. Executed by the project owner on their own machine: 149 held-out texts classified via gpt-4o-mini, precision 97.44% / recall 55.07% / FPR 1.25% (Finding 6). The run also exposed an ablation-contamination bug, now guarded by `tests/unit/test_ablation_isolation.py`. Configs L/M still pending a clean re-run |
| 29 | Load/performance testing | DECLINED, not achievable with integrity | No realistic load-testing environment here |
| 30 | Chaos/failure testing | PARTIAL | Audit-log-failure-never-breaks-a-request: tested. Detector/policy exception handling: not tested — directly related to the Section 8 gap above |
| 31 | Security regression corpus | **PARTIAL — improved** | 744 text examples + 37 agent traces + Attack Replay Lab. Stratified seeded 60/20/20 train/val/**held-out test** split now exists (`dataset/processed/splits.json`); test split used once. Agent traces are self-authored — stated threat to validity |
| 32 | Dataset provenance | DONE | `dataset/README.md`, `docs/research/README.md` |
| 33 | Evaluation, historical baseline preserved | DONE | v0.1/v0.2/v0.3 replay snapshots kept, never overwritten — and independently re-verified byte-for-byte after a sandbox reset |
| 34 | Ablation studies | **DONE** | 11-config causal ablation over an agent-trace benchmark (`scripts/run_ablation.py`). Produced 5 findings including two null results and one that overturned an earlier conclusion. `docs/research/README.md` |
| 35 | Semantic/ML detection | **PARTIAL — real, benchmarked, shipped off-by-default** | Learned lexical classifier (TF-IDF + calibrated logistic regression), `app/detectors/ml_classifier/`. Head-to-head on an identical held-out split (`scripts/compare_baselines.py`): recall 27.54% -> 85.51% (3.10x), precision 100.00% -> 93.65%, FPR 0.00% -> 5.00%. Not a transformer and not claimed to be. Its measured cost drove a policy change (Finding 5): the provenance-escalation rules it would have shipped with were removed after the ablation showed them net-negative |
| 36 | Future custom LLM | DECLINED, per the doc's own instruction | Explicitly out of scope for a hardening phase |
| 37 | Security testing (SAST etc.) | PARTIAL | Dependency scanning yes. SAST, secret scanning, fuzzing: not added |
| 38 | Threat model | PARTIAL | Covers every implemented detector in depth. Broader categories (insider threats, compromised dependencies) not yet added as their own entries |
| 39 | Security disclosure lifecycle | PARTIAL | Basic `SECURITY.md` exists. Supported-versions table, formal response process: not added |
| 40 | Release engineering gates | PARTIAL | v0.3.0 was tagged with a full passing test suite. An automated, enforced release-gate checklist: not implemented |
| 41 | Backward compatibility | DONE, as a practice | Auth was specifically designed off-by-default so it wouldn't break anything existing |
| 42 | Documentation cleanup | PARTIAL | Ongoing discipline throughout. A dedicated, systematic re-read of every claim: not yet done as its own pass |
| 43 | Industry-readiness gate | NOT YET ATTEMPTED | Real, valuable, explicitly wants separate scores, not one number |
| 44 | Final red-team review | NOT YET ATTEMPTED | Partially achievable within sandbox limits |
| 45 | Final deliverable | NOT YET ATTEMPTED | Should come after the above, not before |
| 46 | Final principle | ONGOING | The guiding standard for all of the above |

## Reading this table honestly

Counts drift as work lands; recount from the table rather than trusting this paragraph. As of the last update: 11 DONE, 17 PARTIAL, 5 DECLINED with stated reasoning, 6 NOT YET ATTEMPTED, the remainder N/A or ongoing. That is not "hardening complete" — it is an honest snapshot of an incremental effort, exactly as Section 46 asks for.

Two rows moved recently and are worth naming, because both moved on evidence rather than effort: **§34 ablation studies** went NOT ATTEMPTED → DONE, and **§35 semantic/ML detection** went DECLINED → PARTIAL. §35 had been declined on the reasoning that building and fairly evaluating a semantic detector was too large for a hardening pass. That turned out to be wrong: a learned lexical classifier trained on the existing dataset was achievable, and it produced the project's largest single security improvement. The earlier judgement is left visible in the git history rather than quietly overwritten.

## Reconstruction note

This entire repository, including this file, was rebuilt after a sandbox reset wiped the working directory mid-session. The rebuild was verified, not assumed: a full test run (154 tests) passed cleanly, and the evaluation numbers were independently re-derived by rolling detector patterns back to their true historical states and re-running `scripts/replay_lab.py` — every number matched the pre-reset originals exactly (v0.1: 95.35%/11.88%, v0.2: 96.77%/17.39% with 19 newly-caught attacks and 0 regressions, v0.3: 96.83%/17.68%). That match is itself evidence this document's own standard was followed during recovery, not just during the original build.
