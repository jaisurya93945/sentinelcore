# Changelog

Every entry here corresponds to a real, tested commit — see `git log` for the full history, and `docs/research/README.md` for how the measured numbers were produced.

**Two separate things are versioned in this project, on purpose:** the package version below (semver, tracks the whole application) and the Attack Replay Lab's detector-pattern tags (`v0.1`/`v0.2`/`v0.3` inside `dataset/processed/replay_snapshots/`, tracking prompt_injection/obfuscation pattern iterations specifically). They share number formats by coincidence, not by design — don't read "package v0.3.0" and "detector patterns v0.3" as the same axis.

## Unreleased

Working through `docs/hardening/MASTER_PROMPT.md`-derived hardening selectively, not exhaustively — see `docs/hardening/STATUS.md` for which sections were tackled and which were explicitly declined, with reasoning, rather than attempted and faked.

### Added
- Authentication + role-based authorization — `SENTINELCORE_API_KEYS` ("key:role,..."), three roles (viewer/operator/admin), applied via a real FastAPI dependency to every scan/tool-call/mcp/proxy/audit endpoint. **Off by default** — every existing test and the local quickstart work unchanged with no keys configured; this is a documented default, not a silent gap. Health check and the dashboard's static HTML shell stay unauthenticated by design. Dashboard JS prompts for a key on 401 and holds it in memory only for that page load — never persisted.
- Simplified 3 roles from the 5 originally sketched (Viewer/Auditor/Operator/Administrator/Service) — stated explicitly in `app/core/auth.py`'s docstring as a deliberate collapse, not a silent simplification.
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
