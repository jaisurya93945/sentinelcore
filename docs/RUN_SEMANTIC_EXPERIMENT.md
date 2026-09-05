# Running the semantic-detector experiment

This is the one experiment that cannot run in the development sandbox: `api.openai.com` is blocked there at the network proxy (verified — `x-deny-reason: host_not_allowed`). Everything else in this repository reproduces offline.

## Why it matters

It tests the paper's central mechanism with a **third detector class**. Findings 4 and 5 argue that provenance-aware policy is worth something only when the detector's findings are precise *within the ambiguous confidence band* — not simply when the detector is strong. Two classes have been measured (lexical rules, learned lexical). A semantic detector is the missing one.

**The prediction, recorded before running:** a stronger semantic detector should **not** automatically make provenance more valuable — it should move where the useful operating point sits. If instead the provenance gain simply grows with detector quality, **§5.4 of the paper is wrong and must be rewritten.** Both outcomes are worth reporting; the second is the more interesting one.

## If you hit a 429 (daily request limit)

**Your cached results are safe.** Every classification is written to disk the moment it succeeds, so an interrupted run loses nothing but the outstanding calls. Re-running the same command requests only what is missing.

The runner now distinguishes a **per-minute** limit (retried automatically with exponential backoff) from a **per-day** quota (not retried — no amount of waiting inside one process fixes a daily cap).

Three ways forward, cheapest first:

1. **Resume tomorrow.** Same command. Only the outstanding calls are requested.
   ```bash
   python scripts/run_semantic_experiment.py            # resumes from cache
   ```

2. **Split it across days with `--limit`**, staying under your quota:
   ```bash
   python scripts/run_semantic_experiment.py --limit 40 --texts-only
   ```
   `--texts-only` does just the held-out split — that is the headline detection result and only needs 149 calls total. Trace warming (another ~292) can wait.

3. **Add minimum credit to the account.** Free-tier accounts have very low requests-per-day caps. A small prepaid balance moves the account to the first paid tier, where per-day limits rise by orders of magnitude. The experiment itself costs **under two cents** — the limit is the obstacle, not the price.

If you are hitting *per-minute* rather than per-day limits, add `--delay 1` to space the calls out.

## Changing the model

```bash
SENTINELCORE_SEMANTIC_MODEL=gpt-4o python scripts/run_semantic_experiment.py
```
Note this changes the cache key, so switching models means paying for the calls again. It does **not** help with a daily request cap, which is account-level rather than per-model.

## Steps

```bash
export OPENAI_API_KEY=sk-...
pip install -r requirements-semantic.txt

# 1. See the cost before spending anything
python scripts/run_semantic_experiment.py --estimate
#    -> ~441 calls, roughly $0.01-0.02 on gpt-4o-mini

# 2. Run it (responses cached to disk; re-runs are free)
python scripts/run_semantic_experiment.py

# 3. Re-run the ablation -- do NOT set the env var
python scripts/run_ablation.py
#    Semantic is now configs L and M, controlled by the ablation itself.
#    Setting SENTINELCORE_SEMANTIC_DETECTOR_ENABLED would leak the detector
#    into EVERY config including the rules-only baseline and invalidate the
#    comparison -- that bug is fixed, but the env var is still the wrong
#    control here. L/M read from the on-disk cache, so this costs nothing.

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
