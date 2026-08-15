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
- **No obfuscation resistance:** unicode tricks, zero-width characters, and encoding evasion are not covered here -- that is a separate detector (Phase 2, obfuscation, not yet built).
- **No multi-turn or cross-message detection:** each `detect()` call only sees the single input text passed to it.
- **Not yet benchmarked against a real dataset.** Precision/recall/F1 will be published once Phase 4 (Dataset & Evaluation) exists -- no accuracy claims are made until then.

## Not yet implemented

See the Current Status table in `README.md` for the full list (obfuscation, RAG poisoning, agent/tool misuse, output leakage, risk engine, policy engine).
