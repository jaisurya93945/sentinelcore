# Running the semantic-detector experiment

This is the one experiment that cannot run in the development sandbox: `api.openai.com` is blocked there at the network proxy (verified — `x-deny-reason: host_not_allowed`). Everything else in this repository reproduces offline.

## Why it matters

It tests the paper's central mechanism with a **third detector class**. Findings 4 and 5 argue that provenance-aware policy is worth something only when the detector's findings are precise *within the ambiguous confidence band* — not simply when the detector is strong. Two classes have been measured (lexical rules, learned lexical). A semantic detector is the missing one.

**The prediction, recorded before running:** a stronger semantic detector should **not** automatically make provenance more valuable — it should move where the useful operating point sits. If instead the provenance gain simply grows with detector quality, **§5.4 of the paper is wrong and must be rewritten.** Both outcomes are worth reporting; the second is the more interesting one.

## Steps

```bash
export OPENAI_API_KEY=sk-...
pip install -r requirements-semantic.txt

# 1. See the cost before spending anything
python scripts/run_semantic_experiment.py --estimate
#    -> ~441 calls, roughly $0.01-0.02 on gpt-4o-mini

# 2. Run it (responses cached to disk; re-runs are free)
python scripts/run_semantic_experiment.py

# 3. Re-run the ablation with the semantic detector active
SENTINELCORE_SEMANTIC_DETECTOR_ENABLED=true python scripts/run_ablation.py

# 4. Confidence intervals on the new configurations
python scripts/statistical_validation.py
```

## What to compare

Detection, on the same held-out split all three detectors share:

| Detector | Recall | FPR |
|---|---|---|
| Rules | 18.6% [12.2, 28.7] | 0.5% |
| Learned @0.80 | 72.0% [60.4, 83.7] | 1.1% |
| **Semantic** | *(step 2 prints this)* | |

Provenance's value, which is the actual test:

| Detector | Δ APR from provenance | Δ BCR |
|---|---|---|
| Learned, aggressive threshold (0.35) | +2.4 | −9.4 |
| Learned, shipped threshold (0.50) | +11.8 | −7.1 |
| **Semantic** | *(step 3 prints this)* | |

## Reading the result honestly

- If the semantic Δ APR lands near or below +11.8 → the mechanism holds; provenance is bounded by precision-in-the-band, not detector strength.
- If it lands substantially higher → the mechanism is wrong. Rewrite §5.4 rather than reframing the number.
- If detection recall is high but the provenance gain collapses → also consistent with the mechanism, and worth reporting: a detector confident enough to block on its own leaves provenance nothing to add. That is the same ceiling effect already documented for the HIGH-severity oracle.

## Two cautions

**Data egress.** This detector sends scanned text to a third party. For a security gateway that is a genuine decision, not a footnote — the text being scanned may itself contain secrets or PII. It is off by default for that reason, and the local detectors remain the default path.

**Prompt sensitivity.** The classification prompt is deliberately minimal — no chain-of-thought, no multi-sample voting. A better prompt would produce better numbers and a worse experiment, because the comparison of interest is detector *class*, not prompt engineering. If you change the prompt, bump `PROMPT_VERSION` so the cache does not serve stale results under new conditions.
