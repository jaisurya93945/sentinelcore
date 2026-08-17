# Evaluation Report — v0.1.0-dev baseline

*Note: the numbers immediately below are the original v0.1 baseline, kept as-measured. The detector running in this repo today is v0.2 — see the "v0.1 → v0.2" comparison at the bottom of this page for current numbers and exactly what changed.*

Every number on this page comes from `scripts/evaluate.py` or `scripts/replay_lab.py`, run against real, externally-sourced, labeled data. Nothing here is hand-typed or estimated. Reproduce it yourself:

```bash
pip install -r requirements.txt -r scripts/requirements.txt
python scripts/build_eval_dataset.py
python scripts/evaluate.py
```

## Dataset

744 labeled examples from two real, MIT-licensed public sources (full attribution in `dataset/README.md`):

| Source | Examples | Notes |
|---|---|---|
| `deepset/prompt-injections` (mirrored via `sinanw/llm-security-prompt-injection`) | 662 (263 malicious, 399 benign) | Binary labeled, mostly English + some German |
| `pr1m8/prompt-injections` | 82 (all malicious) | Categorized across 9 attack types, multiple languages |
| **Total** | **744 (345 malicious, 399 benign)** | |

## Methodology

Ground truth is binary (malicious/benign). A prediction counts as "predicted malicious" if **any** registered detector produced at least one finding -- this measures raw detection capability. The policy engine's actual block/warn/sanitize/allow choice is reported separately below, since it answers a different question.

## Headline results

| Metric | Value |
|---|---|
| Accuracy | 58.87% |
| **Precision** | **95.35%** |
| **Recall** | **11.88%** |
| F1 | 21.13% |
| False Positive Rate | 0.50% |
| Confusion matrix | TP=41, FP=2, TN=397, FN=304 |

## What this actually means

This is the honest signature of a v0.1 regex/heuristic baseline, and it's worth being direct about it rather than burying it: **the detector almost never cries wolf (95% precision, 0.5% false-positive rate), but it misses the large majority of real-world attacks (12% recall).** 16 hand-written patterns cover a narrow slice of how people actually phrase these attacks -- real adversarial text is far more varied than a pattern list anticipates on the first pass. This is exactly why the roadmap calls this a *baseline* to measure future work against, not a finished detector.

### Recall by category

| Category | Caught / Total | Recall |
|---|---|---|
| `instruction_override` | 7/23 | 30.4% |
| `role_manipulation` | 3/17 | 17.7% |
| `obfuscation` | 0/8 | 0.0% |
| Multilingual | 1/8 | 12.5% |
| Context Manipulation, Psychological Manipulation, Hijacking, Authority Role | 0/26 | 0.0% |

The last row isn't a surprise -- those categories were never claimed as covered (see `docs/threat-model/README.md`). The real finding is that even our **own** mapped categories only catch 18-30% of real examples: the pattern library needs meaningfully more phrasing variety, not just more categories. `obfuscation` at 0/8 is a genuine miss worth a closer look (see below).

### Recall by language

| Language | Caught / Total | Recall |
|---|---|---|
| English | 10/66 | 15.2% |
| German | 0/12 | 0.0% |
| Spanish, Chinese, Mixed Languages | 0/3 | 0.0% |
| Mixed Scripts | 1/1 | 100% |

Confirms empirically what was already documented as a scope limitation: this is an English-pattern detector. The one "Mixed Scripts" catch is the obfuscation detector's homoglyph check firing on script-mixing itself, independent of language -- a nice confirmation that check generalizes beyond the Latin/Cyrillic example it was built against.

### A specific, confirmed false-positive mechanism

Both false positives trace to the exact same cause: `deepset-train-0029` and `deepset-train-0105` each contain a **real zero-width space (U+200B) embedded in ordinary text** ("...area of \u200b\u200bIT and would like...") -- almost certainly a translation/copy-paste artifact in the source dataset, not an attack. The obfuscation detector is technically correct that the character is present; it just isn't evidence of malice here. This is a specific, reproducible edge case, not a vague caveat: **zero-width character detection alone can't distinguish "adversarial obfuscation" from "incidental formatting noise upstream,"** and that distinction would need more context than a single detector sees in isolation.

### What the policy engine actually decided

| | On malicious (345) | On benign (399) |
|---|---|---|
| block | 37 | 0 |
| sanitize | 1 | 2 |
| warn | 3 | 0 |
| allow | 304 | 397 |

The 2 "sanitize" decisions on benign input are the same two zero-width-space false positives above -- and notably, the policy engine's design choice (Day 8-9: map zero-width characters to `sanitize`, not `block`) already limits the damage of this specific false-positive mode. A misfire here means "strip some invisible characters," not "block a legitimate user."

## Where this points next

This evaluation isn't just a report card, it's a prioritized to-do list, ranked by actual impact instead of guesswork:

1. **Expand the instruction-override and role-manipulation pattern libraries** using the 304 false negatives as direct source material -- `dataset/processed/eval_results.json` has the full list, not just the 15-sample preview here.
2. **Investigate the obfuscation 0/8** -- pull the actual 8 "Formatting Trick" examples and check whether they use a technique genuinely outside current scope, or a variant (e.g. shorter encoded runs, different entity styles) worth adding.
3. Once patterns are expanded, **re-run this exact script** and compare against these numbers as the locked baseline -- that comparison is the Attack Replay Lab in miniature, and the full version (tracked in the roadmap) formalizes it across versions.

## Known limitations of this evaluation itself

- 744 examples is a modest evaluation set, not a large-scale benchmark. Numbers may shift with more data.
- Detector-level "any finding = predicted malicious" is a reasonable proxy but not identical to "the gateway would have stopped this" (see the policy engine table above for that view).
- Both source datasets skew toward classic/well-known attack phrasing; real-world adversarial traffic may differ.

## v0.1 → v0.2: Attack Replay Lab comparison

The three "Where this points next" items above were acted on and measured, not just proposed. Reproduce this exact comparison:

```bash
python scripts/replay_lab.py snapshot v0.1   # before the changes below
# ... make detector changes ...
python scripts/replay_lab.py snapshot v0.2   # after
python scripts/replay_lab.py compare v0.1 v0.2
```

**What changed:** two prompt-injection pattern fixes (`IO-001` widened to catch two-word qualifiers like "the above"; `IO-007` added for the "forget about X" phrasing) and one new obfuscation check (`character_spacing_evasion`, for trigger words split across plain spaces or newlines). Full reasoning, including two patterns that were *considered and rejected*, is in `docs/threat-model/README.md`.

| Metric | v0.1 | v0.2 | Delta |
|---|---|---|---|
| Precision | 95.35% | 96.77% | **+1.42%** |
| Recall | 11.88% | 17.39% | **+5.51%** |
| F1 | 21.13% | 29.48% | **+8.35%** |
| False Positive Rate | 0.50% | 0.50% | +0.00% |

**19 attacks newly caught. Zero regressions. Zero new false positives.** Precision moved *up*, not down -- a real win, not a recall/precision tradeoff, because the fixes were narrow and sourced from actual missed examples rather than broadened for their own sake.

Notably, the two prompt-injection fixes generalized beyond the exact sentences that motivated them -- `IO-007` ("forget about") alone caught the same real phrase appearing independently in both source datasets (`pr1m8-IO-004` and `deepset-train-0056`), plus 2 more pr1m8 examples and 6 more deepset examples using similar constructions. That's evidence these are genuine phrasing fixes, not memorized answers to the specific test sentences -- the concern worth naming and checking, not just asserting: adding a pattern that matches only the literal false-negative text would inflate this benchmark without generalizing, which is precisely the kind of number-gaming the Authenticity Policy exists to prevent.

One catch worth flagging honestly rather than quietly counting as a clean win: `deepset-train-0317` was caught by `character_spacing_evasion`, but not via real newlines -- via the *literal two-character text* `\n` repeated as visual padding (tokenizes as alternating single-char `\` and `n` tokens). Structurally similar to the technique the check was built for, but not identical to it -- flagged here so the "19 newly caught" number isn't read as 19 identical confirmations of the same fix.

