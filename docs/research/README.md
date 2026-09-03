# Evaluation Report — v0.1.0-dev baseline

*Note: the numbers immediately below are the original v0.1 baseline, kept as-measured. The detector running in this repo today is v0.3 — see the "v0.1 → v0.2 → v0.3" comparison at the bottom of this page for current numbers and exactly what changed.*

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

Ground truth is binary (malicious/benign). A prediction counts as "predicted malicious" if **any** registered detector produced at least one finding.

## Headline results (v0.1 baseline)

| Metric | Value |
|---|---|
| Accuracy | 58.87% |
| **Precision** | **95.35%** |
| **Recall** | **11.88%** |
| F1 | 21.13% |
| False Positive Rate | 0.50% |
| Confusion matrix | TP=41, FP=2, TN=397, FN=304 |

## What this actually means

This is the honest signature of a v0.1 regex/heuristic baseline: **the detector almost never cries wolf (95% precision, 0.5% false-positive rate), but it misses the large majority of real-world attacks (12% recall).** 16 hand-written patterns cover a narrow slice of how people actually phrase these attacks.

### A specific, confirmed false-positive mechanism

Both false positives trace to the exact same cause: `deepset-train-0029` and `deepset-train-0105` each contain a real zero-width space (U+200B) embedded in ordinary text -- almost certainly a translation/copy-paste artifact in the source dataset, not an attack. The obfuscation detector is technically correct that the character is present; it just isn't evidence of malice here.

## v0.1 → v0.2: Attack Replay Lab comparison

```bash
python scripts/replay_lab.py snapshot v0.1
# ... make detector changes ...
python scripts/replay_lab.py snapshot v0.2
python scripts/replay_lab.py compare v0.1 v0.2
```

**What changed:** two prompt-injection pattern fixes (`IO-001` widened to catch two-word qualifiers like "the above"; `IO-007` added for "forget about X") and one new obfuscation check (`character_spacing_evasion`).

| Metric | v0.1 | v0.2 | Delta |
|---|---|---|---|
| Precision | 95.35% | 96.77% | +1.42% |
| Recall | 11.88% | 17.39% | +5.51% |
| F1 | 21.13% | 29.48% | +8.35% |
| False Positive Rate | 0.50% | 0.50% | +0.00% |

**19 attacks newly caught. Zero regressions. Zero new false positives.** Precision moved *up*, not down. The two prompt-injection fixes generalized beyond the exact sentences that motivated them -- `IO-007` alone caught the same real phrase appearing independently in both source datasets, plus more examples never specifically targeted.

One catch worth flagging honestly: `deepset-train-0317` was caught by `character_spacing_evasion`, but via the *literal two-character text* `\n` repeated as visual padding, not real newlines -- structurally similar to the technique the check was built for, but not identical.

## v0.2 → v0.3: patterns added for MCP tool-poisoning coverage

Three new prompt_injection patterns (fake authority tags, hidden secondary instructions, secrecy demands -- full reasoning in `docs/threat-model/README.md`) were added while building MCP tool scanning, not primarily to move this benchmark. Re-running it anyway, as always:

| Metric | v0.2 | v0.3 | Delta |
|---|---|---|---|
| Precision | 96.77% | 96.83% | +0.06% |
| Recall | 17.39% | 17.68% | +0.29% |
| F1 | 29.48% | 29.90% | +0.42% |
| FPR | 0.50% | 0.50% | +0.00% |

1 attack newly caught (`deepset-test-0000`), 0 regressions, 0 new false positives. Small, because these patterns were built for a different attack shape (tool descriptions), not tuned against this dataset.

## Known limitations of this evaluation itself

- 744 examples is a modest evaluation set, not a large-scale benchmark.
- Detector-level "any finding = predicted malicious" is a proxy, not identical to "the gateway would have stopped this."
- Both source datasets skew toward classic/well-known attack phrasing; real-world adversarial traffic may differ.
- No formal train/validation/held-out split exists yet -- everything here is one evaluation set, re-run after every detector change. A held-out set that's never used for pattern development is a real, tracked gap (`docs/hardening/STATUS.md`, section 31).
