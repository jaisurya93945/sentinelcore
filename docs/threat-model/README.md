# Threat Model

## Implemented: Prompt Injection (Direct Attacks)

**Detector:** `app/detectors/prompt_injection/`
**Method:** Rules + heuristics (regex pattern matching) -- v0.1 baseline, no ML/semantic detection yet.

### Categories covered

| Category | What it catches | Example |
|---|---|---|
| `instruction_override` | Attempts to make the model ignore, disregard, or override prior instructions | "ignore all previous instructions" |
| `system_prompt_extraction` | Attempts to extract or reveal the system prompt / configuration | "what are your instructions?" |
| `role_manipulation` | Jailbreak persona framing, "no restrictions" framing | "you are now DAN" |

### Known limitations (documented, not hidden -- per the Authenticity Policy)

- **Paraphrase evasion:** an attacker who rewords a known pattern (synonyms, different sentence structure) will not be caught. This is pattern matching, not semantic understanding.
- **False positives on meta-discussion:** legitimate text *about* prompt injection (security research, this repo's own docs) can trigger these patterns. There is no context-awareness yet.
- **No obfuscation resistance in this detector:** unicode tricks, zero-width characters, and encoding evasion are handled by a separate detector -- see below.
- **No multi-turn or cross-message detection:** each `detect()` call only sees the single input text passed to it.
- **Not yet benchmarked against a real dataset.** Precision/recall/F1 will be published once Phase 4 (Dataset & Evaluation) exists -- no accuracy claims are made until then.

## Implemented: Obfuscation

**Detector:** `app/detectors/obfuscation/`
**Method:** Character/encoding-level checks -- deterministic, no ML. Unlike prompt_injection, this detector doesn't look at what the text *means*, only how it's encoded.

### Categories covered

| Category | What it catches | Example |
|---|---|---|
| `zero_width_characters` | Invisible Unicode characters used to split up filtered words | ZWSP hidden mid-word |
| `bidi_control_characters` | Directional override characters that change how text *displays* without changing its bytes ("Trojan Source") | U+202E right-to-left override |
| `unusual_whitespace` | Non-standard space characters (non-breaking space, em/en spaces, etc.) | word-splitting via U+00A0 |
| `mixed_script_homoglyph` | A single word mixing scripts (e.g. Latin + Cyrillic look-alikes) | Cyrillic "а" swapped into "admin" |
| `encoded_payload_suspected` | Long base64-like character runs that may hide an encoded payload | 40+ char base64-charset blob |
| `entity_encoding_obfuscation` | Heavy use of HTML/numeric character entities | `&#105;&#103;...` repeated |
| `control_characters` | Raw ASCII control bytes in the input | null bytes, escape characters |

### Why this detector exists: a concrete example

A zero-width space hidden inside the word "ignore" is **not** caught by the prompt_injection detector -- the literal phrase match fails because the word is no longer contiguous. The obfuscation detector catches it instead, by flagging the zero-width character itself. This is tested and enforced, not just claimed -- see `tests/integration/test_layered_detection.py`.

This is the actual argument for a layered gateway instead of one clever detector: no single check catches everything, but the combination catches more than either alone.

### Known limitations (documented, not hidden)

- **Mixed-script detection uses Unicode character *names*, not real Unicode script properties** -- a lightweight heuristic (Python's stdlib `unicodedata` doesn't expose script directly), so it only recognizes LATIN/CYRILLIC/GREEK confusables today. A full Unicode script-property lookup is a candidate future dependency.
- **Encoded-payload detection is a length heuristic, not a decoder.** It flags long base64-*looking* runs without decoding or inspecting them, and will false-positive on legitimate long tokens (hashes, API keys, session IDs).
- **Pure non-Latin-script text is intentionally not flagged** -- only script-*mixing within a single word* is treated as suspicious, so the detector doesn't penalize non-English input.
- **Not yet benchmarked against a real dataset**, same as prompt_injection -- no accuracy claims until Phase 4.

## Not yet implemented

See the Current Status table in `README.md` for the full list (RAG poisoning, agent/tool misuse, output leakage, actual sanitization execution, evaluation/benchmarking).

## Implemented: Risk Engine

**Module:** `app/services/risk_engine.py`
**Method:** Deterministic severity-weighted scoring -- no ML, no statistical model. Every score is fully explainable: the highest-severity finding sets the base (LOW=10, MEDIUM=30, HIGH=60, CRITICAL=90), each additional finding adds 15% of its own weight on top, capped at 100.

### Known limitations

- **Confidence is not used in scoring.** All v0.1 detectors are deterministic rule matches, not calibrated ML, so every finding is treated as certain. Confidence-weighted scoring only becomes meaningful once a calibrated detector actually exists.
- **The 15% "additional finding" factor is a chosen constant, not a benchmarked value.** It hasn't been tuned against a labeled dataset -- that's Phase 4 work.
- **No historical/session signals yet** -- each scan is scored independently of any prior scans from the same user or session.

## Implemented: Policy Engine

**Module:** `app/services/policy_engine.py`, configured by `app/services/policy.yaml`
**Method:** Two layers, most-severe-decision-wins:
1. **Per-finding-type rules** -- e.g. `instruction_override: block` forces that decision whenever the type appears, regardless of score.
2. **Risk-score thresholds** -- fallback for any finding type without an explicit rule (`block: 70`, `sanitize: 50`, `warn: 25` by default).

### Design notes

- `sanitize` is used for findings that are mechanically fixable (zero-width characters, bidi overrides, unusual whitespace, control characters -- stripping them is well-defined). `block` is used where there's no safe partial fix, like an actual instruction override.
- **SANITIZE is a decision the policy engine can return -- nothing in v0.1 actually performs the strip-and-rescan yet.** Building that transform, and re-running detection on the cleaned text, is tracked as future work, not hidden as already done.
- Policy is fully external and editable (`app/services/policy.yaml`) -- no code change needed to adjust which finding types block/warn/sanitize, or to change thresholds.
- Policy is reloaded from disk on every request in v0.1. Fine for a baseline; caching it at startup is a natural optimization once latency matters.
