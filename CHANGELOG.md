# Changelog

Every entry here corresponds to a real, tested commit — see `git log` for the full history, and `docs/research/README.md` for how the measured numbers were produced.

## Unreleased

### Added
- RAG context scanning — `retrieved_documents` on `/api/v1/scan`, findings tagged by `origin` (`input` vs `context:<i>`) to distinguish direct from indirect prompt injection. No new detector needed; reuses the existing two.
- Reverse proxy gateway — `POST /v1/chat/completions`, OpenAI-path-compatible. Point an existing client's `base_url` at SentinelCore; BLOCK decisions never reach the upstream provider (verified with a mocked-upstream test asserting zero calls, not just a status code). Configurable upstream via `SENTINELCORE_UPSTREAM_BASE_URL`.
- Output security — new PII and secret/credential detectors, wired into both `/api/v1/scan` (`output_text` field) and the proxy's actual response path. Matched values are always redacted before reaching a `Finding` — never stored raw. Proxy now scans and can block on both the request *and* the response.
- Audit logging — every decision from `/api/v1/scan` and both proxy stages persisted to SQLite, queryable via `GET /api/v1/audit/recent`. Metadata only (scan_id, timestamp, endpoint, risk score, decision, finding types/severities) — deliberately never raw text or finding evidence, since a "redacted" preview built from detectors with known gaps would be a false guarantee, not real safety.
- Docker — multi-stage `Dockerfile`, non-root user, `docker-compose.yml` with a persistent audit-DB volume. Not build-tested in this project's dev environment (no Docker available there) — flagged explicitly in the file itself, not glossed over.
- Dependency scanning — `pip-audit` added as a real, blocking CI job against both `requirements.txt` and `requirements-dev.txt` (now split from a single mixed file, so the Docker image doesn't ship test tooling). Clean as of this writing.
- Agent/tool-call inspection — `POST /api/v1/scan/tool-call` combines deterministic tool-name authorization (`tool_policy.yaml`: allow/warn/sanitize/human_approval/block) with content scanning of arguments and tool responses (untrusted input, same principle as RAG documents). New `HUMAN_APPROVAL` decision, specifically for actions that shouldn't be fully automated or fully blocked — v0.1 returns the decision, doesn't implement collecting the approval itself.
- MCP tool discovery scanning — `POST /api/v1/scan/mcp-tools`, accepts real MCP `tools/list` shape directly. Recursively scans every `description` field (including nested per-property descriptions in `inputSchema`) for tool poisoning. Added 3 new prompt_injection patterns for real tool-poisoning phrasing (fake authority tags, hidden secondary instructions, secrecy demands) — verified against the actual current MCP spec before building, and re-benchmarked afterward (1 attack newly caught, 0 regressions, 0 new false positives).

### Known gaps (documented, not hidden)
- Streaming (`stream: true`) is explicitly rejected with a clear error, not silently mishandled
- Not yet tested against a real LLM provider — the dev sandbox has no network access to verify that end-to-end
- SANITIZE still doesn't transform anything anywhere in the codebase — it's a valid decision, nothing executes it yet
- Output BLOCK still costs the upstream call — post-hoc filtering can stop a leak from reaching the client, not the cost of generating it
- No Luhn validation on credit card matches, no name/address PII detection (needs NLP, not regex)

## v0.2 (detector patterns) — part of v0.1.0-dev

### Added
- `character_spacing_evasion` obfuscation check — catches trigger words split into single characters via plain spaces or newlines (found via real evaluation examples, not hypothetical)
- `IO-007` prompt injection pattern — "forget about X" phrasing variant

### Fixed
- `IO-001` now matches two-word qualifiers ("the above", "the previous"), not just single words

### Rejected (documented, not silently skipped)
- Bare "act as [role]" — too common in legitimate prompts, would trade recall for a larger precision loss
- Named-figure impersonation — same reasoning, needs semantic judgment, not a regex

### Measured (`scripts/replay_lab.py compare v0.1 v0.2`)
- Recall: 11.88% → 17.39% (+5.5pp)
- Precision: 95.35% → 96.77% (+1.4pp)
- False positive rate: unchanged at 0.50%
- 19 attacks newly caught, 0 regressions, 0 new false positives

## v0.1.0-dev — 2026-08-15/16

### Added
- Repo scaffold, FastAPI skeleton, `Finding`/`ScanResult` schema
- Detector plugin interface + registry (`@register_detector`)
- Prompt injection detector — 16 rules across `instruction_override`, `system_prompt_extraction`, `role_manipulation`
- Obfuscation detector — zero-width characters, bidi control characters, unusual whitespace, mixed-script homoglyphs, suspected encoded payloads, entity encoding, control characters
- Risk engine — deterministic severity-weighted scoring, 0-100
- Policy engine — YAML-configurable per-type rules + score thresholds, most-severe-wins
- `/api/v1/scan` — full pipeline wired end-to-end (detect → score → decide)
- Real evaluation against 744 labeled examples from two MIT-licensed public datasets (`deepset/prompt-injections`, `pr1m8/prompt-injections`)
- Attack Replay Lab — version-tagged snapshot + diff tooling
- 54 tests, 98% coverage, GitHub Actions CI on every push/PR
