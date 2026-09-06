# Prior work, and what is actually novel here

Written because the fastest way to lose a reviewer is to claim as a discovery something already published. Each finding below is classified as **replication**, **extension**, or **novel**, with the prior work named.

## Finding 6 — a lightweight classifier outperformed an LLM detector: **REPLICATION**

Our result (TF-IDF + logistic regression, F1 0.8939, recall 85.5% against gpt-4o-mini's 55.1%) reproduces a pattern already established in the literature:

- **The Mirror design pattern** (arXiv:2603.11875) reports a linear SVM over character n-grams reaching **F1 0.9207 against Meta's Prompt-Guard-2 at F1 0.5914** on the same test set, arguing that strict data geometry outperforms model scale.
- **Galinkin & Sablotny (NVIDIA, 2024)** report a Random Forest over Snowflake embeddings at **F1 0.9601 on JailbreakHub, where PromptGuard reached 0.3029**.
- **GuardNet** (arXiv:2606.05566) surveys this family and reaches the same conclusion.

Our classifier is the same architectural family — character n-grams into a linear model — and lands in the same performance region. **This is independent replication on a different corpus, not a discovery.** It is worth reporting as replication (the field has a replication deficit) but the paper must not present it as new.

## Findings 8 and 9 — LLM confidence has no usable middle: **NOVEL, as far as we can establish**

We found no prior work measuring the *distribution* of an LLM detector's self-reported confidence and connecting it to the viability of a graded policy layer built on top. The specific claims:

1. Self-reported probability takes **8 distinct values across 149 predictions**, with **1** in the 0.50–0.80 band and **100% of errors made confidently**.
2. Token log-probabilities do not recover the signal — they saturate harder, **92% at exactly 0.0 or 1.0**.
3. Consequence: provenance/authority weighting built on that confidence gains **+1.2 points**, against **+11.8** for a calibrated classifier on the same benchmark with the same policy engine.

Adjacent but distinct: the calibration literature documents LLM overconfidence and round-number quantisation of verbalised probabilities. **That phenomenon is known.** What we have not found stated is its *architectural consequence* — that it disables the graded policy layer most current layered defences depend on. That connection is the contribution, and it should be framed as such rather than as a discovery about language models.

## Finding 5 — oracle evaluation overstates layered defences: **NOVEL, methodological**

We found no prior work quantifying the gap between oracle-detector and real-detector evaluation of a provenance mechanism (+47.0 against +1.2 to +11.8 points here). Related work evaluates defences *with* strong detectors; we are arguing that doing so systematically favours whatever is layered on top, because the layer's cost is paid in false positives an oracle cannot produce.

## The competitive position, stated plainly

Do **not** claim SentinelCore's detector is state of the art. On the evidence:

- Our recall (85.5%) is respectable but the field has stronger classifiers, and we have not yet benchmarked against them. `scripts/benchmark_industry.py` closes that gap against Meta Prompt Guard 2.
- We have no production deployment, no adaptive-attack evaluation, and no comparison against commercial systems (Lakera, ProtectAI).
- The over-defense problem is measured in the literature via the **NotInject** benchmark (ProtectAI's PIGuard, ACL 2025), where PromptGuard scores as low as **0.88%** over-defense accuracy. We have not evaluated on it. Our hard-benign traces are a much weaker proxy.

**Where the work does compete is methodological**: pre-registered predictions, retracted claims left on the record, cross-version independent reproduction, and an ablation that isolates policy mechanisms from detector quality. That is a real contribution to a field where, on the evidence of the survey literature, most systems are evaluated once, favourably, by their own authors.
