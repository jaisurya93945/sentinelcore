# Threat Model

## Implemented: Prompt Injection (Direct Attacks)

**Detector:** `app/detectors/prompt_injection/`
**Method:** Rules + heuristics (regex pattern matching) -- v0.1 baseline, no ML/semantic detection yet.

### Categories covered

| Category | What it catches | Example |
|---|---|---|
| `instruction_override` | Attempts to make the model ignore, disregard, or override prior instructions | "ignore all previous instructions" |
| `system_prompt_extraction` | Attempts to extract or reveal the system prompt / configuration | "what are your instructions?" |
| `role_manipulation` | Jailbreak persona framing, "no restrictions" framing, fake authority tags | "you are now DAN", "<IMPORTANT>...</IMPORTANT>" |

### Known limitations (documented, not hidden -- per the Authenticity Policy)

- **Paraphrase evasion:** an attacker who rewords a known pattern will not be caught. This is pattern matching, not semantic understanding.
- **False positives on meta-discussion:** legitimate text *about* prompt injection can trigger these patterns.
- **No obfuscation resistance in this detector:** unicode tricks, zero-width characters, and encoding evasion are handled by a separate detector -- see below.
- **No multi-turn or cross-message detection:** each `detect()` call only sees the single input text passed to it.
- **Not yet benchmarked against a real dataset without measurement.** Precision/recall/F1 are published in `docs/research/README.md` and re-run whenever patterns change.

## Implemented: Obfuscation

**Detector:** `app/detectors/obfuscation/`
**Method:** Character/encoding-level checks -- deterministic, no ML.

### Categories covered

| Category | What it catches | Example |
|---|---|---|
| `zero_width_characters` | Invisible Unicode characters used to split up filtered words | ZWSP hidden mid-word |
| `bidi_control_characters` | Directional override characters that change how text *displays* without changing its bytes ("Trojan Source") | U+202E right-to-left override |
| `unusual_whitespace` | Non-standard space characters | word-splitting via U+00A0 |
| `mixed_script_homoglyph` | A single word mixing scripts (e.g. Latin + Cyrillic look-alikes) | Cyrillic "а" swapped into "admin" |
| `encoded_payload_suspected` | Long base64-like character runs | 40+ char base64-charset blob |
| `entity_encoding_obfuscation` | Heavy use of HTML/numeric character entities | `&#105;&#103;...` repeated |
| `control_characters` | Raw ASCII control bytes in the input | null bytes, escape characters |
| `character_spacing_evasion` | Trigger words split into single characters via plain whitespace/newlines | `I g n o r e` or one letter per line |

### Why this detector exists: a concrete example

A zero-width space hidden inside the word "ignore" is **not** caught by the prompt_injection detector -- the literal phrase match fails because the word is no longer contiguous. The obfuscation detector catches it instead. Tested and enforced -- see `tests/integration/test_layered_detection.py`.

### Known limitations

- Mixed-script detection uses Unicode character *names*, not real Unicode script properties -- only recognizes LATIN/CYRILLIC/GREEK confusables.
- Encoded-payload detection is a length heuristic, not a decoder -- false-positives on legitimate long tokens (hashes, API keys).
- Pure non-Latin-script text is intentionally not flagged -- only script-*mixing* is suspicious.

## Implemented: Output Security (PII + Secrets)

**Modules:** `app/detectors/pii/`, `app/detectors/secrets/`
**Wired into:** `/api/v1/scan` (`output_text` field) and `/v1/chat/completions` (the assistant's actual reply).

Two detectors, kept separate: PII and secrets have very different false-positive profiles and severities.

### Categories and policy

| Category | Detector | Severity | Policy |
|---|---|---|---|
| `aws_access_key`, `private_key` | secrets | CRITICAL | block |
| `generic_api_key`, `db_connection_string` | secrets | HIGH | block |
| `jwt_token`, `bearer_token` | secrets | MEDIUM | warn |
| `ssn`, `credit_card` | pii | HIGH | block |
| `email_address`, `phone_number`, `ip_address` | pii | LOW | warn |

### A deliberate design decision: findings never contain the raw secret

Every match is redacted (first two + last two characters, everything else masked) before it goes into a `Finding`.

### Output blocking has a cost the input side doesn't

An **input** BLOCK prevents the upstream call entirely. An **output** BLOCK cannot -- by the time a secret is found in the model's reply, the upstream call has already happened and been paid for.

### Known limitations

- No Luhn validation on credit cards. No name/address detection (needs NLP, not regex).

## Implemented: RAG Context Scanning (Indirect Prompt Injection)

**Module:** `app/api/v1/scan.py` (orchestration only -- no new detector)

The existing detectors, applied to RAG-retrieved documents in addition to the user's own input. Every finding carries an `origin`: `"input"`, `"context:<index>"`, or `"output"`.

### Known limitations

- Origin doesn't yet affect scoring or policy.
- No conflicting-instruction detection, no source trust/provenance tracking.

## Implemented: Reverse Proxy Gateway

**Endpoint:** `POST /v1/chat/completions` -- deliberately matching OpenAI's own path.

Scans the request and the response through the identical pipeline as `/api/v1/scan`. BLOCK on the input side means the upstream is never called -- proven via a mocked-upstream call-count assertion, not just a status code check. The client's `Authorization` header is forwarded through untouched.

### Streaming

Real streaming, not buffer-then-dump. Rescanned incrementally after every chunk, with a mid-stream cutoff via a synthetic `finish_reason: "content_filter"` chunk. Verified live: the specific violating chunk is fully suppressed, not just "some tokens after."

**Known limitation, stated precisely:** a detectable pattern split exactly across a chunk boundary (e.g. `AKIA` in one chunk, the rest of an AWS key in the next) can partially leak before the second chunk completes the pattern. Not fixable by scanning faster -- a property of chunk boundaries not aligning with detector patterns. Re-scanning the full accumulated text on every chunk is O(n) per chunk, O(n^2) total over a long stream.

### Known limitations

- Malformed/unrecognized request bodies are forwarded through unscanned rather than blocked.
- Only `/v1/chat/completions` is proxied -- no generic passthrough for other endpoints.
- SANITIZE doesn't transform anything here either.
- Not tested against a real LLM provider -- no network access to one from this sandbox.

## Implemented: Agent / Tool-Call Inspection

**Modules:** `app/services/tool_policy.py`, `app/detectors/tool_arguments/`
**Endpoint:** `POST /api/v1/scan/tool-call`

Two independent checks: (1) deterministic tool-name authorization via `tool_policy.yaml` (allow/warn/sanitize/human_approval/block by name, not risk-scored -- "is this agent allowed to call payment.transfer" doesn't get more true by combining severities), and (2) content scanning of arguments and, if provided, the tool's response (untrusted input, same principle as a RAG document). Final decision is the more severe of the two, arrived at independently.

### HUMAN_APPROVAL

Added specifically for tool authorization. **v0.1 only returns this decision; nothing implements collecting an actual approval.**

### Known limitations

- The tool-argument detector runs on all text, not just tool arguments -- false-positive risk on ordinary technical chat.
- No blanket policy.yaml rules for tool_arguments categories, deliberately -- severity gradient drives the threshold response instead.
- No intent alignment (comparing what the user asked for against what the agent is about to do) -- needs semantic understanding, not regex.
- No tool chaining, step limits, or session tracking.

## Implemented: MCP Tool Discovery Scanning

**Endpoint:** `POST /api/v1/scan/mcp-tools` -- accepts the real MCP `tools/list` shape directly.

Scans for tool poisoning: hidden instructions embedded in a tool's `description`. MCP's own documentation states a tool description "is part of the prompt context sent to the model... the instruction manual for the AI." Descriptions are extracted **recursively** -- MCP schemas nest a `description` per property inside `inputSchema` too.

Three patterns added specifically for this: fake authority tags (`<IMPORTANT>`, `<SYSTEM>`), hidden secondary instructions ("before using this tool, you must..."), secrecy demands ("do not tell the user").

### Known limitations

- No structural JSON Schema validation -- checks description text only.
- No tool name impersonation detection.
- No live MCP server connection -- scans definitions you provide, doesn't connect to a server itself.

## Implemented: Audit Logging

**Module:** `app/services/audit_log.py`, queryable via `GET /api/v1/audit/recent`

Every decision gets persisted to SQLite: `scan_id`, timestamp, endpoint, an optional `detail` (a controlled identifier like a tool name), risk score, decision, and a findings summary.

### What's deliberately never stored

Raw input text, output text, and finding `evidence` are never persisted. The tempting alternative -- a "redacted" text preview using the same detectors that have documented gaps -- would be a false sense of safety.

### Known limitations

- Synchronous SQLite, one connection per write -- untested under real concurrent load.
- No schema migration support -- a new column requires a fresh database file.
- No retention policy, no rotation, no export tooling.
- No identity/session tracking.

## Implemented: Dashboard

**Files:** `app/static/dashboard.html`, `app/api/v1/dashboard.py`

A single static HTML page, no build pipeline. Polls `GET /api/v1/audit/recent` every 5 seconds. Screenshotted against live seeded data before shipping, which caught and fixed two real issues: an illegible risk indicator, and tool-call/MCP entries with no indication of which tool was involved.

### Known limitations

- Polling, not push. No filtering, search, or export. Shows the most recent 30 events only.

## Implemented: Docker + Dependency Scanning

**Files:** `Dockerfile`, `docker-compose.yml`, `.dockerignore`; `.github/workflows/ci.yml`

Multi-stage build, non-root user. **Not build-tested in this project's own development environment** -- no Docker available in the sandbox. `pip-audit` runs against both requirements files on every push/PR as a real blocking gate.

### Known limitations

- Docker: no build test, no published image, no image-size optimization beyond the basic split.
- Dependency scanning covers Python packages only -- no container image scanning, SBOM, or signature verification.

## Implemented: Authentication & Authorization

**Module:** `app/core/auth.py`

Real API-key authentication with 3 roles (viewer/operator/admin), applied via a genuine FastAPI dependency to every scan/tool-call/mcp/proxy/audit endpoint. **Off by default**: `SENTINELCORE_API_KEYS` unset means every endpoint behaves exactly as before this existed -- a real, named risk if the gateway is network-reachable without setting it. Health checks and the dashboard's static HTML shell stay unauthenticated by design.

### A real simplification, stated as one

The hardening spec this was built against sketched five roles (Viewer/Auditor/Operator/Administrator/Service). This implementation has three -- there's no admin-configurable state and no per-tool service identity system yet to justify five distinct labels.

### Known limitations

- No key rotation or revocation tooling.
- No per-key rate limiting or usage tracking.
- The proxy requires its own key in addition to the client's upstream Authorization header -- two different credentials for two different things.
- No credential storage abstraction -- keys live in plain environment configuration.

## Implemented: Real Sanitize Enforcement

**Module:** `app/services/sanitizer.py`

Until this existed, SANITIZE was a decision the policy engine could return with nothing behind it -- displayed, never executed. `decision` and `enforcement_status` are now separately represented (not conflated into one field that could silently mean either "we recommend this" or "we did this"): `decision` always reflects the final, actionable outcome after any enforcement attempt; `enforcement_status` (`enforced` / `escalated` / `not_implemented` / `not_applicable`) explains how it got there.

The mechanism is strip-or-normalize-then-**mandatory re-scan**, not strip-and-trust. Collapsing `"I g n o r e   a l l   i n s t r u c t i o n s"` reveals `"Ignore all instructions"` underneath -- a real instruction override -- and the re-scan catches it, escalating the decision to BLOCK rather than silently returning "sanitized" text that's still dangerous. Verified directly, not assumed: `tests/unit/test_sanitizer.py`, plus end-to-end tests in both `/api/v1/scan` and the proxy showing the actual forwarded request body contains the cleaned text, not the original.

### Which finding types have a real sanitizer

`zero_width_characters`, `bidi_control_characters`, `unusual_whitespace`, `control_characters`, `character_spacing_evasion`. Anything else mapped to SANITIZE in `policy.yaml` (there currently is nothing else) would come back `not_implemented` rather than silently pretending to clean it.

### A real, honest edge case in the character-spacing sanitizer

Collapsing a **multi-word** character-spaced run (e.g. an entire spaced-out sentence) glues words together with no boundaries -- `"Ignoreallpreviousinstructions"`, not `"Ignore all previous instructions"` -- because the reconstruction logic mirrors the *detector's own* existing behavior (see `test_character_spacing_evasion_detected_via_newlines` in `test_obfuscation.py`, which predates this sanitizer). The glued result then won't match phrase-based patterns requiring whitespace, so multi-word cases can come back `enforced` even though a human reading the reconstructed text would recognize the intent. A **single** spaced-out word surrounded by normal text doesn't hit this -- see `tests/unit/test_sanitizer.py` for both cases, verified directly rather than assumed.

### Known limitations

- Only wired into `/api/v1/scan` (main input text only, not retrieved_documents or output_text) and the proxy's non-streaming input path. Streaming, tool-call, and MCP endpoints still return SANITIZE without enforcing it.
- A SANITIZE verdict influenced by findings from more than one text source (e.g. both the main input and a retrieved document) can't be fixed by rewriting just one of them -- reported as `not_applicable` rather than partially sanitizing something that wouldn't address why the decision was made.
- HUMAN_APPROVAL still has no real approval-collection mechanism behind it -- a separate, unaddressed gap.

## Implemented: Provenance-Aware Risk Scoring

**Module:** `app/services/origin_trust.py`, wired into `app/services/risk_engine.py`

Until this existed, `Finding.origin` was tracked faithfully and then ignored -- neither the risk engine nor the policy engine ever read it, which made "provenance-aware" a false claim. An instruction-override finding in a user's own message and the identical finding inside a retrieved document produced the same score and the same decision.

Severity weights are now scaled by origin. Measured effect on an identical MEDIUM finding: `input` -> 30 (warn), `context:N` -> 45 (warn), `tool_arguments:*` -> 54 (**sanitize**). Same text, different provenance, different outcome.

### What is a modeling choice vs. an empirical result

The trust **ordering** (user input < RAG context < tool/MCP output) is the claim, and it follows from the standard indirect-prompt-injection threat model: attacker-controlled external content reaching the model's context is the core danger, and a user talking to their own assistant is not the same threat as an external party injecting instructions into a conversation they aren't part of. The specific **multipliers** (1.0 / 1.5 / 1.8) are a stated modeling choice, **not calibrated or empirically derived** -- anyone re-deriving them from real data should expect different numbers. They live in one table for exactly that reason.

### The ablation control is deliberate, not legacy

`calculate_risk_score(findings, use_origin_trust=False)` reproduces the pre-provenance behaviour exactly. This is the control condition for the ablation study asking whether provenance-awareness actually improves anything -- removing it would make that experiment impossible.

### Measured: the current benchmark cannot evaluate this

Running the full 744-example evaluation after this change produced **exactly zero difference** (precision 96.83%, recall 17.68%, FPR 0.50%, 0 newly caught, 0 regressions). That is not a null result about provenance -- it is a structural limitation of the benchmark: every example is scanned as `input` origin, so origin-weighting cannot influence any outcome by construction. This is direct evidence that a text-classification benchmark cannot evaluate an agent-security mechanism, and it is the concrete argument for adopting an agent-level benchmark (AgentDojo) rather than extending this one.

## Implemented: Learned Classifier Detector (optional, OFF by default)

**Module:** `app/detectors/ml_classifier/`, trained by `scripts/train_ml_detector.py`

TF-IDF (word 1-2 + char 3-5 grams) into a calibrated logistic regression. Held-out test: **P=93.65% R=85.51% F1=89.39% FPR=5.00% AUC=0.964**, against the rules baseline **measured on the identical split**: 27.54% recall, 100.00% precision, 0.00% FPR — a 3.10x recall improvement at a real precision cost. (The 17.68% figure is the baseline over all 744 examples and is not comparable to a split-based number.) Stratified seeded 60/20/20 split; the test split is touched once and never used for threshold selection.

**It is a learned LEXICAL classifier, not a transformer and not semantic understanding.** It generalises within training vocabulary and inherits that data's language bias. Calling it "AI-powered semantic detection" would be false.

### Why it is off by default

A 10x false-positive increase (0.50% -> 5.00%) is the right trade for some deployments and the wrong one for others; the operator decides. Enabling it by default would also make scikit-learn a mandatory dependency for a project whose core value is being small and deterministic. Measured agent-level cost: benign workflow completion drops 93.3% -> 80.0%.

### Fail-open, deliberately and explicitly

If scikit-learn is absent, the model file is missing, or inference raises, this detector logs once and returns no findings rather than raising. That is a real security trade-off, stated rather than buried: an optional detector must not take down a gateway whose rules-based detectors, risk engine, policy engine and tool authorization are all still functioning correctly. Failing the whole request would convert degraded detection into a total outage.

### Acted on our own measurement

`ml_injection@<origin>` escalation rules are deliberately **not** in the shipped default policy. Finding 5 measured them as net-negative: 0pp attack prevention gained, 20pp benign completion lost, because provenance escalation converts a probabilistic detector's false positives into hard blocks on external content. They remain reproducible as an experimental override in `scripts/run_ablation.py`. Shipping a default the project's own experiment showed to be harmful would contradict the Authenticity Policy.

## Implemented: Human Approval Workflow

**Modules:** `app/services/approvals.py`, `app/api/v1/approvals.py`

`HUMAN_APPROVAL` was previously a decision returned with nothing behind it — the same defect `SANITIZE` had, and worse here, because it is reserved for the highest-consequence actions in the system. A tool call now creates a real, queryable approval record with a lifecycle: `PENDING → APPROVED | DENIED | EXPIRED`.

`ToolCallResult` gains `approval_id` and `enforcement_status`. The action is authorised **only** when status is `approved`; pending, denied, expired, missing, and store-failure all refuse.

### Fail-closed on expiry — the load-bearing decision

An unanswered approval becomes `EXPIRED`, and expiry is a **refusal, not consent**. The alternative would convert an operator being asleep into authorisation for a privileged action, which is precisely what a human-in-the-loop control exists to prevent. It also means a denial-of-service against the approval channel degrades to "nothing executes" rather than "everything executes". A late approval cannot revive an expired record.

### Separation of duty

Deciding an approval requires the **admin** role; the scan endpoints require **operator**. If the role that triggers an action could also authorise it, the control would be decorative.

### Known limitations, stated rather than implied away

- **No notification delivery.** No email, Slack, or pager. Records are created and queryable; getting a human's attention is an integration concern, and shipping a fake one would be theatre.
- **`decided_by` is unverified.** This project has no identity system to bind it to, so it is an audit annotation, not an authenticated claim. Labelled as such in the API schema.
- **Expiry is evaluated lazily on read**, not by a scheduler. `expires_at` is authoritative; status catches up when someone looks. Safe only because `PENDING` and `EXPIRED` are both non-permitting — if either permitted execution this would be a vulnerability.
- **Nothing enforces the approval at execution time.** SentinelCore returns the decision and tracks the record; the calling application must check `permits_execution` before acting. The gateway cannot execute the tool on the caller's behalf, so it cannot make this guarantee for them.

## Not yet implemented

See the Current Status table in `README.md` and `docs/CAPABILITY_MATRIX.md` for the full list: rate limiting, conflicting-instruction detection, source trust/provenance tracking, origin-aware policy, enterprise/multi-tenant scale, HUMAN_APPROVAL enforcement, sanitize enforcement for streaming/tool-call/MCP paths.
