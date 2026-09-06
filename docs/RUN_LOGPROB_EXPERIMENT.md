# Running the log-probability experiment

**One command per day, three days at 50 RPD — but the answer usually arrives on day one.**

## What it tests

Finding 8 measured that gpt-4o-mini's *self-reported* probability takes only 8 distinct values across 149 predictions, puts exactly one prediction in the 0.50–0.80 band, and gets **100% of its errors wrong confidently**. A graded policy layer built on that has nothing to act on.

This asks a narrower question: **is that a property of LLM detection, or of asking the model to state a number?**

Same model, same task, same texts. The only change is reading `P(YES)` out of the model's own token distribution instead of its narration of it.

## The falsification condition, fixed in advance

| Outcome | Meaning |
|---|---|
| Logprob confidence is **also** quantised and avoids the ambiguous band | Finding 8 generalises to LLM detection |
| Logprob confidence is **continuous** and better calibrated | **Finding 8 is about a common implementation choice, not about language models.** The paper must narrow the claim |

The second outcome is a correction to our own framing. It is written down here before the run so it cannot be quietly reinterpreted afterwards.

## Day 1 — 50 calls, and probably your answer

```bash
export OPENAI_API_KEY=sk-...
python scripts/logprob_experiment.py --limit 50
```

Look at `distinct values`. The verbalized run produced **8 across 149**. If the logprob run produces 40+ across 50, the distribution question is already settled and the remaining days only sharpen the precision/recall comparison.

## Days 2–3 — finish the split

```bash
python scripts/logprob_experiment.py --limit 50
```

Same command. Cached calls are free, so it resumes automatically. When all 149 are collected it prints the full head-to-head against the verbalized run on identical texts.

## Reading the output

```
                            logprobs   verbalized
distinct values                   ...            8
in 0.50-0.80 band                 ...            1
errors                            ...           32
confident errors                  ...           32
```

The script prints a verdict, but check the numbers yourself — it applies a threshold rule and thresholds are not judgement. If the result is mixed, it says so rather than picking a side.

## Cost

149 calls, roughly **$0.008**. The constraint is the daily request cap, not money.

## Note

This is a *different measurement* of the same texts, so it uses a separate cache namespace. It will not overwrite or reuse the verbalized results — both are kept, which is what makes the head-to-head possible.
