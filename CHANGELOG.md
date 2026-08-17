# Changelog

Every entry here corresponds to a real, tested commit — see `git log` for the full history, and `docs/research/README.md` for how the measured numbers were produced.

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
