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

---

# Agent-Trace Ablation Study

The first action-level experiment in this project. Reproduce with:

```bash
python scripts/build_agent_traces.py
python scripts/run_ablation.py
```

## Why a second benchmark exists

The 744-example text benchmark scans every example as `input` origin. When provenance-aware scoring was added, re-running it produced **exactly 0.00% change** on every metric — not because provenance does nothing, but because that benchmark is *structurally incapable* of varying provenance. Measuring whether an unsafe **action** is prevented requires an event trace, not a labeled sentence.

## What this benchmark is, and is not

37 deterministic agent traces (22 attack, 15 benign) replayed through the pipeline. **It does not run a live LLM.** The claim "the unsafe action in this trace was blocked" is strictly weaker than "an agent driven by a real model was stopped." It is a bridge to a real agent benchmark (AgentDojo), not a substitute.

**Threat to validity, stated plainly:** these scenarios were authored by the same author as the system under test, which systematically favors the system. Three partial mitigations: attack categories come from published taxonomies rather than from what SentinelCore catches; 9 scenarios are deliberately included that the system is *expected to fail* (paraphrased injection, non-English, semantic-only attacks, legitimate destructive operations); and hard benign cases are included so utility cost is measured rather than assumed. **If APR were 100%, the benchmark would be broken.** It is 81.8%.

Prevention counts only `BLOCK` / `SANITIZE` / `HUMAN_APPROVAL`. `WARN` is excluded deliberately — a warning stops nothing, and counting it as prevention is the same "decision reported as enforcement" error this project treats as a correctness bug.

## Results

| Config | Mechanisms | APR | BCR |
|---|---|---|---|
| A content-only | detectors + risk + policy | 72.7% | 100.0% |
| B + prov scoring | origin trust *score* scaling | **72.7%** | 100.0% |
| C + tool authz | tool-name authorization | **81.8%** | 93.3% |
| D scoring+authz | both | 81.8% | 93.3% |
| E + prov **rules** | origin-conditioned *policy rules* | **81.8%** | 93.3% |
| F oracle(HIGH) flat | perfect-recall oracle detector | 100.0% | 93.3% |
| G oracle(HIGH) + prov | oracle + provenance | 100.0% | 93.3% |
| H oracle(MED) flat | oracle at *ambiguous* confidence | 81.8% | 93.3% |
| I oracle(MED) + prov | oracle + provenance | **90.9%** | 93.3% |

Attack prevention by category:

| Category | A | B | C | D |
|---|---|---|---|---|
| compositional | 75% | 75% | **100%** | 100% |
| unauthorized_tool | 75% | 75% | **100%** | 100% |
| direct_injection | 60% | 60% | 60% | 60% |
| indirect_injection | 75% | 75% | 75% | 75% |
| mcp_poisoning | 67% | 67% | 67% | 67% |
| exfiltration | 100% | 100% | 100% | 100% |

## Finding 1 — tool authorization is the component that causes the improvement

+9.1pp APR, and the category breakdown shows *why*: the gain is entirely in `compositional` and `unauthorized_tool` (both 75% → 100%), exactly the categories where the attack is a privileged action with clean-looking arguments. Content scanning cannot catch `database.delete(table="logs")` — there is nothing malicious in the text. Only deterministic name-based authorization stops it.

This is a real security/utility trade-off, not a free win: BCR drops 100% → 93.3%. The cost is a specific, identified scenario (BN-009: a user legitimately deleting an out-of-retention table) that the tool policy blocks. That is the correct behavior for the configured policy and a genuine usability cost, reported rather than hidden.

## Finding 2 — NEGATIVE RESULT: provenance scoring is subsumed by categorical policy

**Provenance-aware risk scoring produced no measurable improvement (A → B: 72.7% → 72.7%; C → D: 81.8% → 81.8%).** This is reported as a null result rather than dropped.

Diagnosed cause, verified directly: provenance altered the decision in only 3 of 37 scenarios, and never in a way that changed an outcome. The policy engine applies **categorical per-finding-type rules before score thresholds**, and `instruction_override: block` fires regardless of score. On a poisoned RAG document the score rises 62 → 92 with provenance enabled — and the decision is `block` either way.

**First hypothesis:** provenance was applied at the wrong *layer* — scaling a number that a categorical rule overrides cannot change behaviour. So it should be applied to the rule itself.

## Finding 3 — the fix for Finding 2 also failed, and that is the real result

Config E implements exactly that hypothesis: `origin_rules` keyed `<finding_type>@<origin_prefix>`, consulted before the flat per-type rules, escalating for untrusted origins *and* relaxing for the user's own input (so it is a genuine trade-off, not a one-way ratchet).

**It changed the decision in 0 of 37 scenarios. APR and BCR are identical to config D.**

Diagnosing *that* produced the finding that explains both negative results at once. The 4 attacks that survive every configuration are exactly the deliberately-hard ones, and all four produce **zero findings**:

| Scenario | Why it evades | Findings produced |
|---|---|---|
| DI-004 | paraphrased, no literal trigger phrase | 0 |
| DI-005 | non-English (German) | 0 |
| II-004 | purely semantic, no trigger phrase | 0 |
| MCP-003 | soft phrasing ("recommended to also share…") | 0 |

**Provenance re-weights findings that already exist. When detection produces nothing, there is nothing to re-weight, re-rule, or escalate. Zero multiplied by any trust factor is still zero.**

### The consequence, stated plainly

Provenance-aware policy — at *any* layer, score or rule — is **fundamentally gated on detection recall**. It cannot rescue a missed detection; it can only change what happens to a detection that already fired. With a regex detector at 17.68% recall, roughly four in five real attacks never reach the policy layer at all, so no amount of policy sophistication above it can matter.

This reframes the project's own roadmap. Adding richer policy, session tracking, or action-graph reasoning on top of a 17.68%-recall detector is optimising the layer that is not the bottleneck. It also generates a falsifiable prediction about the published literature: provenance/authority mechanisms (AuthGraph, PACT, Progent) should show large gains specifically *because* they are paired with detection that does not depend on phrase matching — taint tracking or model-based classification — and would degrade toward these null results if paired with a lexical detector. That is directly testable and is the strongest experiment this project could run next.

Both ablation controls (`use_origin_trust=False`, `use_origin_rules=False`) are retained deliberately, since the experiment is only re-runnable while every condition remains available.


## Finding 4 — provenance works, but only inside a narrow confidence band

Findings 2 and 3 showed provenance doing nothing. To test whether that was a property of provenance or of *this system's detection*, an **oracle detector** was added: perfect recall on attacker-authored content, by ground-truth label. It is an experimental upper bound, never registered in the running system.

It deliberately does **not** flag TA-001 or MS-004, whose payload is a privileged action with entirely clean text. No content detector, however perfect, can see those — marking them would rig the oracle.

Run at two severities, because the first run had a **ceiling effect** worth reporting rather than hiding: a HIGH-severity oracle scores 60, already clearing the `sanitize` threshold of 50, so the outcome is decided before provenance is consulted (F = G = 100%). A MEDIUM-severity oracle scores 30 — WARN, not prevention — leaving headroom to ask the actual question.

**Result: H → I is +9.1pp APR (81.8% → 90.9%) at zero utility cost (BCR unchanged at 93.3%).**

The category breakdown confirms the mechanism rather than just the outcome:

| Category | H (flat) | I (provenance) |
|---|---|---|
| indirect_injection | 75% | **100%** |
| mcp_poisoning | 67% | **100%** |
| direct_injection | 60% | 60% |

Both gains are external-content origins (`context`, `tool_description`) — exactly where the trust model predicts. `direct_injection` is unchanged **by design**: `oracle_injection@input: warn` deliberately declines to escalate the user's own keyboard, which is the relaxation direction that makes this a trade-off rather than a one-way ratchet.

### A methodological error found and corrected

The first corrected run reported +4.6pp. Investigating why `mcp_poisoning` improved while `indirect_injection` did not revealed a real bug: the oracle's origin rules had been written into the flat `rules:` block instead of `origin_rules:`, so they never fired, and the apparent gain came entirely from score-weighting. After the fix the effect is +9.1pp and both categories improve, as the mechanism predicts. Recorded because a result that only makes sense after you stop checking is not a result.

## Synthesis: when does provenance matter?

Three regimes, each measured:

| Detection regime | Provenance effect | Why |
|---|---|---|
| **Missed** (real regex detectors, 17.7% recall) | **None** (A→B, C→D→E all null) | No finding exists to re-weight. 0 × any trust factor = 0 |
| **High confidence** (oracle, HIGH) | **None** (F→G null) | Already blocks on score alone; provenance never consulted |
| **Ambiguous** (oracle, MEDIUM) | **+9.1pp APR, zero utility cost** | The only regime with headroom for provenance to decide |

Provenance-aware policy is neither useless nor a general win. It occupies a **narrow, identifiable band**: detections that fired but are not individually conclusive. That is a precise, falsifiable characterisation, and it directly explains why the published literature reports large gains from provenance/authority mechanisms — those systems pair provenance with detection that produces abundant ambiguous signal (taint tracking, model-based classification), placing them squarely in the third regime. A lexical detector spends most of its time in the first.

**The actionable consequence for this project is unchanged and now quantified: detection recall is the binding constraint.** Under an oracle, APR reaches 100%; the real system reaches 81.8%. The entire 18.2pp gap is detection, not policy.

---

# Finding 5 — the oracle was misleading, and that is the most important result

Finding 4 concluded, from an oracle experiment, that provenance delivers +9.1pp APR at **zero utility cost**. Replacing the oracle with a real learned detector shows that conclusion was an artifact of how the oracle was built.

## The detector

TF-IDF (word 1-2 grams + character 3-5 grams) into a calibrated logistic regression, trained on the same 744-example dataset under a **stratified, seeded 60/20/20 train/validation/test split**. The test split was used once, at the end; confidence bands were chosen on validation. This also closes a gap flagged earlier in this document: the project previously had no held-out set at all.

It is a **learned lexical** classifier — not a transformer, not semantic understanding. It generalises within vocabulary and inherits the training data's language bias. What matters for this experiment is a property regex lacks: it emits a probability, so it can express uncertainty.

| Split | Precision | Recall | F1 | FPR | AUC |
|---|---|---|---|---|---|
| validation | 89.86% | 89.86% | 89.86% | 8.75% | 0.966 |
| **held-out test** | **93.65%** | **85.51%** | **89.39%** | **5.00%** | **0.964** |

Recall against the hand-written regex baseline: **27.54% → 85.51% on the identical held-out split**, a **3.10×** improvement, at a precision cost of 100.00% → 93.65% and FPR 0.00% → 5.00%.

> **Correction.** This was originally reported as 17.68% → 85.51%, a 4.8× improvement. That was an invalid comparison: 17.68% is the rules baseline over all 744 examples, while 85.51% is the classifier on the 149-example held-out split — different datasets. Measured on identical data (`scripts/compare_baselines.py`) the baseline scores 27.54%, and the real improvement is 3.10×. The error was caught while drafting the paper and is recorded rather than silently corrected.

## The result

| Config | Detector | Provenance | APR | BCR |
|---|---|---|---|---|
| C | regex | no | 81.8% | 93.3% |
| H | oracle (MED) | no | 81.8% | 93.3% |
| I | oracle (MED) | **yes** | 90.9% | **93.3%** |
| J | **learned** | no | **100.0%** | 80.0% |
| K | **learned** | **yes** | **100.0%** | **60.0%** |

**Detection recall was indeed the binding constraint** — the learned detector reaches 100% attack prevention, matching the oracle, and lifts every previously-failing category (direct_injection 60→100%, indirect_injection 75→100%, mcp_poisoning 67→100%).

**But provenance is net-negative with a real detector: 0pp APR gain, −20pp benign completion.**

## Why the oracle lied

Under J, the classifier fires at ambiguous confidence on benign external content and the flat rule warns — harmless, the workflow completes. Under K, the origin rule escalates that same uncertain finding to `block` because it arrived from `context`. Three entirely ordinary workflows are destroyed:

| Scenario | Content | J | K |
|---|---|---|---|
| BN-002 | "Summarize the quarterly report" + normal revenue doc | warn | **block** |
| BN-006 | "What does our onboarding doc say about laptops?" | warn | **block** |
| BN-015 | "Search for recent papers on RAG" | warn | **block** |

**Provenance converted the classifier's false positives into hard blocks.** A 5% FPR is tolerable when uncertain findings only warn. It is not tolerable when provenance escalates uncertainty on external content — and in an agent system, *most* content is external.

The oracle had **zero false positives by construction**. That is precisely the assumption that fails in reality, and it is the assumption that made provenance look free.

## Corrected synthesis

1. **Detection recall is the binding constraint.** Quantified on identical held-out data: 27.54% → 85.51% recall moves APR 81.8% → 100%. No policy mechanism produced a comparable gain.
2. **Provenance-aware escalation is not free.** Its value depends entirely on detector **precision within the ambiguous band**, not on the existence of ambiguity. With a perfectly precise detector it is a pure win; with a realistic one it is a net loss.
3. **Oracle experiments systematically overstate provenance mechanisms.** This is a methodological result, and it applies beyond this codebase: any evaluation that grants a defense ground-truth detection will overstate the value of anything layered on top of it, because the layer's cost is paid in false positives the oracle cannot produce.

Finding 4 is superseded. It is retained above, unedited, because the sequence — oracle result, contradicting real-detector result, diagnosis — is the actual contribution.


---

# Statistical Validation

`python scripts/statistical_validation.py` — 10 independent stratified splits, McNemar's exact test, 10,000-sample bootstrap CIs.

## What survives scrutiny

| 10 seeds, mean [95% CI] | Rules | Learned |
|---|---|---|
| Precision | 0.970 [0.883, 1.000] | 0.930 [0.881, 0.965] |
| **Recall** | **0.185 [0.122, 0.287]** | **0.884 [0.829, 0.965]** |
| F1 | 0.308 [0.217, 0.446] | 0.906 [0.872, 0.951] |
| FPR | 0.005 [0.000, 0.022] | 0.058 [0.028, 0.104] |

Recall and FPR intervals do not overlap. **McNemar's exact test rejects the null on 10/10 seeds, max p = 5.6×10⁻⁶.** The detection-recall finding is solid.

### A second single-split artifact, caught by doing this

The previous correction replaced an invalid 4.84× claim with 3.10×, measured on seed 20260903. Over 10 seeds the rules baseline averages **0.185** recall — the single split gave it 0.275, near the *top* of its interval, i.e. unusually favourable to the baseline. The representative improvement is **4.78×**.

So the original 4.84× was approximately right *in magnitude* while being wrong *in method*, and the 3.10× correction was right in method but based on an unrepresentative split. Both single-split figures were artifacts. Only the multi-seed interval is a defensible estimate. This is recorded rather than tidied away because it is a clean demonstration of why single-split results should not be trusted — including our own.

## What does NOT survive scrutiny

Bootstrap 95% CIs on the agent benchmark (22 attack / 15 benign traces):

| Config | APR [95% CI] | BCR [95% CI] |
|---|---|---|
| A rules | 0.727 [0.545, 0.909] | 1.000 [1.000, 1.000] |
| C + tool authz | 0.818 [0.636, 0.955] | 0.933 [0.800, 1.000] |
| H oracle(MED) | 0.818 [0.636, 0.955] | 0.933 [0.800, 1.000] |
| I oracle(MED) + prov | 0.909 [0.773, 1.000] | 0.933 [0.800, 1.000] |
| J learned | 1.000 [1.000, 1.000] | 0.800 [0.600, 1.000] |
| K learned + prov | 1.000 [1.000, 1.000] | 0.600 [0.333, 0.867] |

**Intervals span roughly ±18 points. None of Findings 1, 4 or 5's headline differences are statistically significant at this sample size.**

Specifically:
- Tool authorization's +9.1pp (A→C): **not significant** — intervals overlap heavily.
- Provenance's +9.1pp under oracle (H→I): **not significant**.
- Provenance's −20pp utility cost (J→K): **not significant** — [0.600, 1.000] vs [0.333, 0.867].

### What this does and does not invalidate

It does **not** invalidate the mechanisms, which rest on causal diagnosis rather than rate comparison: the four attacks surviving every rules configuration were verified to produce *zero findings*, and the three benign workflows broken by provenance escalation were individually identified and traced. A verified mechanism plus a non-significant rate difference is weaker than a significant one, but it is not the same as no evidence.

It does mean the **numbers should not be quoted as measured effect sizes**. They are directional, with named mechanisms, on an underpowered benchmark.

**The single highest-value extension to this work is therefore not a new mechanism — it is 5–10× more agent traces.** That is a tractable, unglamorous, and necessary next step, and it is identified here rather than deferred to a vague "future work" line.

---

# v2 Benchmark: 170 traces with externally-authored payloads

The statistical validation above concluded that the highest-value next step was not a new mechanism but more traces. This is that work.

## What changed, and why it matters for validity

The v1 benchmark had two weaknesses, both stated in the paper: self-authorship (scenarios written by the same author as the system) and small n. Both are addressed by sourcing **payload text from the held-out test split** of the public datasets (deepset, pr1m8). That text is externally authored, independently labelled, and held out from the classifier's training *and* threshold selection. We contribute only the structure: which provenance vector carries the payload, and what action follows.

**170 traces (85 attack / 85 benign); 149 carry externally-sourced payloads, 21 are authored.** The 21 are structural attacks (destructive tool calls with clean arguments, exfiltration via tool arguments) and hard benign cases — neither has textual payload to borrow, because the attack *is* the action. They are flagged `authored: true` so their contribution can be separated.

Each held-out text is used in **exactly one trace**. Reusing payloads across delivery vectors would have inflated n while producing correlated samples and falsely narrow CIs.

## Results (n=85/85, bootstrap 95% CIs)

| Config | APR [95% CI] | BCR [95% CI] |
|---|---|---|
| A rules | 0.282 [0.188, 0.377] | 1.000 [1.000, 1.000] |
| B + prov. scoring | 0.306 [0.212, 0.400] | 1.000 [1.000, 1.000] |
| C + tool authz | 0.365 [0.259, 0.471] | 0.988 [0.965, 1.000] |
| E + prov. rules | 0.400 [0.294, 0.506] | 0.988 [0.965, 1.000] |
| H oracle(MED) | 0.365 [0.259, 0.471] | 0.988 [0.965, 1.000] |
| **I oracle(MED) + prov.** | **0.835 [0.753, 0.906]** | 0.988 [0.965, 1.000] |
| **J learned** | **0.941 [0.882, 0.988]** | 0.882 [0.812, 0.941] |
| K learned + prov. | 0.965 [0.918, 1.000] | 0.788 [0.694, 0.871] |

CIs narrowed from roughly ±18 points to ±10, and several comparisons now resolve.

## What is now statistically significant

**Detection dominance.** A (0.282 [0.188, 0.377]) vs J (0.941 [0.882, 0.988]) — intervals nowhere near overlapping. Swapping the detector moves attack prevention by 66 points. No policy mechanism came close.

**The oracle effect.** H (0.365 [0.259, 0.471]) vs I (0.835 [0.753, 0.906]) — **non-overlapping**. Under a ground-truth detector at ambiguous confidence, provenance adds **+47.0 points**, and that is now a real measured effect rather than a suggestive one.

## What is still not significant

**Provenance's benefit with a real detector.** J (0.941) vs K (0.965): +2.4 points, intervals overlap substantially. Its utility cost (BCR 0.882 → 0.788) is borderline — [0.812, 0.941] against [0.694, 0.871] barely overlap at the edges.

**Provenance over rules-based detection.** A→B (+2.4) and C→E (+3.5) both overlap. Note these are now *non-zero*, where v1 measured them at exactly zero; a harder benchmark gives provenance slightly more to work with, but not enough to resolve.

## Finding 5, strengthened by roughly an order of magnitude

The v1 conclusion was that oracle evaluation overstates provenance: +9.1 points under oracle versus 0 with a real detector. On a larger benchmark with externally-authored payloads, the same comparison is:

- **Oracle: +47.0 points, statistically significant, zero utility cost.**
- **Real detector: +2.4 points, not significant, at a ~9 point utility cost.**

That is roughly a **20× overstatement**, and the significance now runs the right way round: the misleading result is the one that is statistically solid, and the real-world result is the one that vanishes into noise. An evaluation that reported only the oracle number would present a large, significant, apparently free improvement for a mechanism that, against a real detector, buys nothing measurable and costs utility.

This is the paper's central claim, and it is now demonstrated on a benchmark whose attack text we did not write.

## A bug found while doing this

The first v2 ablation run showed the oracle configurations scoring *below* the learned classifier — impossible for a ground-truth detector. Cause: the v2 builder did not emit the `oracle_malicious` flag the oracle reads, so it silently saw nothing and the F–I configurations were meaningless. Fixed by marking the payload-carrying event, with structural attacks deliberately left unmarked (their payload is an action with clean text, invisible to any content detector by construction). Recorded because the failure was silent — the configurations produced plausible-looking numbers rather than an error.
