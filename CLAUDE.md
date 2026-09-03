# CLAUDE.md

Context for Claude Code working in this repo. Read this first, then the files it points to — don't ask the user to re-explain project history; it's all here or in the linked docs.

## What this is

SentinelCore — an open-source AI security gateway (input/RAG/output/tool-call/MCP scanning, risk + policy engines, reverse proxy, audit log, dashboard, auth). Part of the CipherAI platform. Built incrementally with Claude across many sessions.

## The one rule that overrides everything else

**Authenticity Policy: never fabricate benchmark numbers, test results, or claims of what's implemented.** If something isn't tested, say so. If a claim can't be verified in this environment, don't make it. This project's entire credibility rests on every number being real and reproducible — see `docs/research/README.md` for how the evaluation numbers are produced (`scripts/evaluate.py`, `scripts/replay_lab.py`), not hand-typed.

## Where the actual state lives (read these before making changes)

- `docs/CAPABILITY_MATRIX.md` — implemented / partial / planned, security gaps, honest competitive positioning. The single best "what's really here" doc.
- `docs/hardening/STATUS.md` — section-by-section status against a specific hardening spec (`docs/hardening/MASTER_PROMPT.md`), with DONE/PARTIAL/DECLINED and reasoning for each.
- `docs/threat-model/README.md` — per-detector design reasoning and known limitations, updated whenever something changes.
- `CHANGELOG.md` — what shipped, when, with the measured deltas.
- `README.md` — quickstart, status table, architecture pointer.

These are living docs. If you implement or change something, update the relevant one(s) in the same commit — don't let them drift from the code.

## Working conventions established so far

- **Detectors are plugins**: subclass `BaseDetector`, `@register_detector`, add one import line to `app/detectors/__init__.py`. No core file changes needed.
- **Decision vs enforcement_status are separate fields** (`app/models/finding.py`) — a decision is a recommendation, `enforcement_status` records whether it was actually enforced. Never report a decision as if it were a completed action. See `app/services/sanitizer.py` for the pattern: sanitize, then mandatorily re-scan before trusting the result.
- **Auth is off by default** (`SENTINELCORE_API_KEYS` unset = unauthenticated, on purpose, so existing tests/local dev keep working) — see `app/core/auth.py`.
- **Every detector-pattern change gets measured**, not just claimed: `python scripts/replay_lab.py snapshot <name>` before and after, then `compare`, and put the real delta in the commit message and `CHANGELOG.md`.
- **Docker is not build-tested** in any dev environment used so far — stated explicitly in `Dockerfile`, don't remove that caveat without actually testing a build.

## Before considering anything "done"

1. `pytest --cov=app tests/ -v` — full suite passing, not just the file you touched.
2. If you touched a detector or policy: re-run the evaluation/replay-lab and report the real numbers.
3. Update `docs/CAPABILITY_MATRIX.md` and/or `docs/hardening/STATUS.md` if what you built changes their claims.
4. Commit with a message that states what was verified, not just what was written.

## Known priority queue (as of the last session, check STATUS.md for current)

Rate limiting, ablation studies, database indexes/migration strategy, real HUMAN_APPROVAL enforcement, sanitize enforcement for streaming/tool-call/MCP paths (currently only wired into `/api/v1/scan` and the proxy's non-streaming path). PyPI packaging is a good, fully-verifiable-in-this-repo next milestone if you want something with a clean finish line.

## What NOT to do

Don't add scaffolding for things with no real logic behind them (agent identity systems, action graphs, memory security abstractions) just to look aligned with an ambitious spec — that's explicitly against this project's own stated principles. If a real provider, load-testing environment, or external infra is required to verify something honestly, say so and don't fabricate the result instead.
