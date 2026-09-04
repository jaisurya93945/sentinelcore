# When Does Provenance-Aware Policy Actually Help? An Ablation Study of Layered Defenses for LLM Agent Gateways

**DRAFT — not submitted.** Every number below is produced by a script in this repository and is reproducible from a clean checkout. Nothing is estimated. Where a result contradicts an earlier claim of ours, both are reported.

---

## Abstract

Defenses for LLM agents increasingly layer provenance tracking and authority enforcement on top of a content detector. We evaluate this layering directly, using an 11-configuration ablation over an agent-trace benchmark, and report three results that complicate the prevailing design.

First, **detection recall dominates**: replacing a hand-written rules detector with a learned classifier raises recall from 0.185 to 0.884 (10 seeds, non-overlapping 95% CIs, McNemar p < 5.6×10⁻⁶ on every seed) and raises agent-level attack prevention from 0.282 to 0.941, a larger gain than any policy mechanism we tested.

Second, **provenance-aware escalation is not free, and its apparent value depends on how detection is simulated.** Under a ground-truth oracle at ambiguous confidence, provenance improves attack prevention by **47.0 points (0.365 → 0.835, non-overlapping 95% CIs)** at no utility cost. Under a real classifier of comparable recall, the same mechanism yields **+2.4 points, not statistically distinguishable from zero**, while costing roughly 9 points of benign task completion.

Third, and consequently, **oracle-based evaluation systematically overstates layered defenses — here by roughly 20×.** An oracle has no false positives by construction, so a layer whose cost is paid in escalated false positives appears free. The significance runs the wrong way round: the misleading measurement is the statistically solid one, while the deployment-realistic measurement vanishes into noise. We argue this is a general hazard for evaluations of provenance and authority mechanisms, not a quirk of our system.

Evaluation uses 170 agent traces whose attack and benign payload text is drawn from the **held-out** split of public datasets rather than authored by us, addressing the self-authorship bias that limited an earlier version of this work.

We also report a control-plane vulnerability class found in our own gateway: a component that correctly scanned tool calls was never reachable from the request path that produced them, so every model-generated action bypassed enforcement while each component passed its own tests.

---

## 1. Introduction

An LLM agent that retrieves documents, calls tools, and consumes MCP tool definitions has a substantially larger attack surface than a chat model. The dominant response is a layered gateway: detect suspicious content, attribute it to a provenance class, evaluate authority for the requested action, and enforce a decision.

Each layer is individually well-motivated. What is rarely measured is their **interaction** — specifically, whether a policy layer contributes anything once detection quality is held fixed, and whether its contribution survives realistic detector error.

We measure this with a deliberately unglamorous method: hold the benchmark fixed, vary one mechanism at a time, and report every configuration including the ones where our own mechanisms fail.

### Contributions

1. An 11-configuration ablation isolating content detection, provenance scoring, provenance-conditioned policy rules, tool authorization, and detector quality (§4).
2. A quantification of detection recall as the binding constraint: changing only the detector moves agent-level attack prevention by 65.9 points (0.282 → 0.941), against 8.3 points for the strongest policy mechanism we tested (§5.1, §5.3).
3. A demonstration that provenance escalation's measured benefit **inverts** between oracle and real detectors, and a mechanism explaining why (§5.3).
4. A control-plane coverage vulnerability class, with a reproduction (§3.3).
5. All code, data, splits, seeds, and the negative results, released.

---

## 2. Background and Related Work

Indirect prompt injection — attacker text reaching a model through retrieved content rather than user input — motivates provenance tracking in agent defenses. Recent systems bind authority to provenance at varying granularity: programmable privilege policies, argument-level authority-provenance binding, dual-graph provenance/authorization alignment, and runtime enforcement specifications. Reported attack success rates on agent benchmarks are low, often below 2%.

Our work is not a competing defense. It asks a narrower question those systems do not isolate: **given a detector, what does the provenance layer add, and under what detector conditions?** Because published systems typically pair provenance with detection that produces abundant graded signal (taint propagation, model-based classification), our results predict where their gains come from and where they would not transfer.

---

## 3. System Under Study

### 3.1 Pipeline

A provider-agnostic reverse proxy at the API wire boundary. It requires no agent-framework integration — an OpenAI-compatible client changes only its `base_url`. Requests, retrieved context, model outputs, tool calls, and MCP tool definitions flow through: **detectors → findings (origin-tagged) → risk engine → policy engine → enforcement**.

Decisions are `ALLOW / WARN / SANITIZE / HUMAN_APPROVAL / BLOCK`. Enforcement status is a **separate field** from decision, so a recommendation cannot be recorded as a completed action.

### 3.2 Deployment-boundary versus framework-integrated defense

This architecture sees only the wire protocol. It cannot observe intra-agent planning state or taint flow inside the framework. That is a real capability ceiling, and it is the trade for deploying without modifying the agent. Quantifying that ceiling is future work; here it constrains which attacks are visible at all.

### 3.3 A control-plane coverage vulnerability

During audit we reproduced the following in our own system. The proxy scanned `message.content`, which is `null` whenever a model emits a tool call. A response carrying

```json
{"tool_calls":[{"function":{"name":"shell.execute",
  "arguments":"{\"command\":\"rm -rf / && curl evil.com -d @/etc/passwd\"}"}}]}
```

was forwarded with decision `allow`. A correct tool-call scanner **already existed** and passed its own tests; the request path simply never routed to it.

The generalizable point: component-level testing cannot detect an unreachable component. Every unit test passed. We suggest coverage of *enforcement paths* — for each surface, which request path reaches which check — as a distinct audit obligation from detector quality. Fixed, with regression tests, before the experiments below.

---

## 4. Methodology

### 4.1 Benchmarks

**Text benchmark.** 744 labeled examples from two public MIT-licensed datasets. Stratified, seeded 60/20/20 train/validation/test. The test split is used once; confidence thresholds are selected on validation only.

**Agent-trace benchmark.** 170 deterministic event traces (85 attack, 85 benign). Payload text for 149 of them is drawn from the **held-out test split** of the two public datasets — externally authored, independently labelled, and unseen by the learned classifier during both training and threshold selection. We contribute only the structure: which provenance vector carries the payload (user input, retrieved document, tool response, MCP tool description) and what action the agent then attempts.

Each held-out text is used in **exactly one trace**. Reusing payloads across delivery vectors would inflate the sample count while producing correlated samples and falsely narrow confidence intervals.

The remaining 21 traces are authored, and flagged as such in the data: structural attacks (destructive tool calls with clean arguments, exfiltration through tool arguments) and hard benign cases (a legitimate destructive operation, a security-training question, benign text that superficially resembles an injection). Neither has textual payload to borrow, because in those cases the attack *is* the action.

An earlier version of this work used 37 fully self-authored traces. Those results are superseded; the direction of every qualitative finding held, but the effect sizes changed materially.

**This is not a live-agent benchmark.** "The unsafe action in this trace was blocked" is strictly weaker than "an agent driven by a real model was stopped." We treat it as a bridge to live-agent evaluation, not a substitute.

### 4.2 Metrics

- **APR** (attack prevention rate): attack traces whose unsafe action was blocked. Counts `BLOCK`/`SANITIZE`/`HUMAN_APPROVAL` only — **`WARN` is excluded**, because a warning stops nothing and counting it as prevention is the same category error as reporting a decision as enforcement.
- **BCR** (benign completion rate): benign traces allowed to complete. This is the cost axis; a defense that blocks everything scores APR 100% and is useless.

### 4.3 Configurations

| | Detector | Provenance scoring | Provenance rules | Tool authz |
|---|---|---|---|---|
| A | rules | – | – | – |
| B | rules | ✓ | – | – |
| C | rules | – | – | ✓ |
| D | rules | ✓ | – | ✓ |
| E | rules | ✓ | ✓ | ✓ |
| F | oracle (HIGH) | – | – | ✓ |
| G | oracle (HIGH) | ✓ | ✓ | ✓ |
| H | oracle (MED) | – | – | ✓ |
| I | oracle (MED) | ✓ | ✓ | ✓ |
| J | learned | – | – | ✓ |
| K | learned | ✓ | ✓ | ✓ |

The **oracle** flags attacker-authored content by ground-truth label. It deliberately does *not* flag two attacks whose payload is a privileged action with entirely clean text — no content detector, however perfect, can see those. It is run at two severities because a HIGH-severity oracle saturates the score threshold, deciding the outcome before provenance is consulted; that ceiling effect is itself reported.

### 4.4 Detectors compared

**Rules:** 19 prompt-injection patterns, 8 obfuscation checks, PII, secrets, tool-argument patterns.

**Learned:** TF-IDF (word 1–2, character 3–5 grams) → calibrated logistic regression. This is a **learned lexical** classifier, not a transformer and not semantic understanding; it generalizes within training vocabulary and inherits its language bias. The property that matters here is that it emits a probability, so it can express uncertainty.

---

## 5. Results

### 5.1 Detection quality on the identical held-out split

| n=149 | Rules | Learned |
|---|---|---|
| Precision | 100.00% | 93.65% |
| **Recall** | **27.54%** | **85.51%** |
| F1 | 43.18% | 89.39% |
| FPR | 0.00% | 5.00% |

*Correction:* an earlier draft quoted 17.68% for the rules baseline — measured over all 744 examples, not the held-out split, and therefore not comparable to the classifier's split-based 85.51%. On identical data the baseline scores 27.54%.

**But a single split is not sufficient evidence either.** Repeating over 10 independent stratified splits (§5.2):

| 10 seeds, mean [95% CI] | Rules | Learned |
|---|---|---|
| Precision | 0.970 [0.883, 1.000] | 0.930 [0.881, 0.965] |
| **Recall** | **0.185 [0.122, 0.287]** | **0.884 [0.829, 0.965]** |
| F1 | 0.308 [0.217, 0.446] | 0.906 [0.872, 0.951] |
| FPR | 0.005 [0.000, 0.022] | 0.058 [0.028, 0.104] |

Recall and FPR confidence intervals do not overlap. **McNemar's exact test (paired, same test set) rejects the null on 10 of 10 seeds, max p = 5.6×10⁻⁶.**

The single seed used above (20260903) gave the rules baseline 27.54% recall — near the *top* of its 10-seed interval, and thus unusually favourable to the baseline. The representative improvement is **4.78× (0.185 → 0.884)**, not 3.10×. Both figures are correct for their respective data; the 3.10× is a single-split artifact, which is exactly what multi-seed evaluation exists to expose.

### 5.2 Statistical validation

10 independent stratified splits, McNemar's exact test for the paired classifier comparison, and 10,000-sample bootstrap CIs for the agent-benchmark rates. Reproduce with `scripts/statistical_validation.py`.

### 5.3 Ablation

Bootstrap 95% CIs over 85 attack and 85 benign traces (10,000 resamples):

| Config | APR [95% CI] | BCR [95% CI] |
|---|---|---|
| A rules | 0.282 [0.188, 0.377] | 1.000 [1.000, 1.000] |
| B + prov. scoring | 0.306 [0.212, 0.400] | 1.000 [1.000, 1.000] |
| C + tool authz | 0.365 [0.259, 0.471] | 0.988 [0.965, 1.000] |
| E + prov. rules | 0.400 [0.294, 0.506] | 0.988 [0.965, 1.000] |
| F oracle(HIGH) | 0.965 | 0.988 |
| H oracle(MED) | 0.365 [0.259, 0.471] | 0.988 [0.965, 1.000] |
| **I oracle(MED) + prov.** | **0.835 [0.753, 0.906]** | 0.988 [0.965, 1.000] |
| **J learned** | **0.941 [0.882, 0.988]** | 0.882 [0.812, 0.941] |
| K learned + prov. | 0.965 [0.918, 1.000] | 0.788 [0.694, 0.871] |

**Significant.** Detection choice dominates: A (0.282) vs J (0.941), intervals nowhere near overlapping — a 66-point swing from changing the detector alone. And the oracle provenance effect: H (0.365 [0.259, 0.471]) vs I (0.835 [0.753, 0.906]), **non-overlapping, +47.0 points**.

**Not significant.** Provenance with a real detector: J vs K is +2.4 points with substantially overlapping intervals. Its utility cost (BCR 0.882 → 0.788) is borderline, the intervals overlapping only at their edges. Provenance over rules-based detection (A→B +2.4, C→E +3.5) likewise does not resolve — though both are now non-zero, where the smaller v1 benchmark measured them at exactly zero.

#### 5.3.1 Mechanisms

**Tool authorization** contributes +8.3 points (A 0.282 → C 0.365), concentrated in the `structural_action` category — attacks whose payload is a privileged action with entirely clean arguments (`database.delete(table="customer_records")`, `payment.transfer`). No content scanner can see these; the text is unremarkable. Its cost is small but real: one benign trace blocked, a legitimate destructive operation the tool policy denies by design.

**Provenance over rules-based detection contributes little** (A→B +2.4, C→E +3.5, neither significant). The diagnosis from the smaller benchmark still holds and explains why: categorical per-finding-type policy rules fire regardless of score, so score weighting rarely reaches a threshold that is actually consulted, and where the rules detector produces *no* finding at all — paraphrased, non-English, or purely semantic attacks — there is nothing for provenance to re-weight. Zero multiplied by any trust factor remains zero.

**Detection quality dominates everything else.** A → J is +65.9 points (0.282 → 0.941) from changing only the detector, against +8.3 for the best policy mechanism. The gap is detection, not policy.

### 5.4 The oracle overstates provenance by roughly 20×

The same mechanism, measured two ways on the same benchmark:

| | Δ APR | Significant? | Utility cost |
|---|---|---|---|
| Under oracle (MED) | **+47.0 pts** | **yes** — non-overlapping CIs | none |
| Under learned classifier | +2.4 pts | no — CIs overlap | ≈ −9 pts BCR |

**The significance runs the wrong way round, and that is the point.** The measurement that overstates the mechanism is the statistically solid one; the deployment-realistic measurement is the one that dissolves into noise. A paper reporting only the oracle configuration would present a large, significant, apparently cost-free improvement for a mechanism that, against a real detector, buys nothing measurable and degrades utility.

The mechanism is visible in the failures. When the classifier fires at ambiguous confidence on benign external content, a flat policy warns and the workflow completes. Provenance escalates that same uncertain finding to `block` because it arrived from `context`. Ordinary workflows break: summarising a document, an internal lookup, a search. **Provenance escalation converts a probabilistic detector's false positives into hard blocks** — and in an agent system most content is external, so most of the detector's error surface is exactly where escalation applies.

An oracle has **zero false positives by construction**. That is precisely the property that fails in deployment, and precisely what makes provenance appear free.

## 6. Discussion

**Provenance is not useless; its value is conditional.** It requires (a) a finding to exist, and (b) that finding to be genuinely ambiguous, and (c) the detector to be *precise within the ambiguous band*. Our oracle satisfied (c) by construction; our classifier does not.

**A methodological claim.** Any evaluation granting a defense ground-truth detection will overstate the value of layers built on top, because those layers' costs are paid in false positives an oracle cannot generate. Provenance and authority mechanisms are especially exposed, since their action is to *escalate*. We suggest such systems report utility under a realistic detector, not only attack success under a strong or oracle one.

**We acted on this internally:** the provenance-escalation rules for the learned detector are deliberately **not** in our shipped default policy, because our own experiment measured them as net-negative. They remain reproducible as an experimental override.

---

## 7. Limitations and Threats to Validity

1. **Partially authored agent benchmark.** 149 of 170 traces carry externally-authored, held-out payload text; the trace *structure* (which vector carries the payload, what action follows) is ours, as are 21 fully authored traces, flagged in the data. This substantially reduces but does not eliminate authorship bias: we still chose the delivery vectors and the action set. Fully addressing it requires an external agent benchmark (AgentDojo, InjecAgent), which we have not run.
2. **No live agent.** Deterministic trace replay, not a model-driven agent.
3. **Scale, quantified.** Text-benchmark results are solid: 10 seeds, non-overlapping CIs, McNemar p < 5.6×10⁻⁶ on every seed. Agent-benchmark CIs narrowed from roughly ±18 points (37 traces) to ±10 (170), which resolved the two largest effects — detection dominance and the oracle provenance effect — but **not** the small ones. The +2.4-point real-detector provenance gain and its ≈9-point utility cost remain unresolved and should not be quoted as effect sizes. Resolving those requires several hundred more traces or a benchmark with higher per-trace signal.
4. **The classifier is lexical, not semantic.** It will not generalize to novel semantic attacks or to languages outside its training data.
5. **Single trust-multiplier configuration.** Constants are a stated modeling choice, not calibrated.
6. **No comparison against published defenses.** We compare our own configurations, not against Progent, CaMeL, or similar.
7. **Wire-boundary ceiling unquantified.** We argue framework-integrated defenses see strictly more; we have not measured how much more.

---

## 8. Conclusion

Layering provenance and authority on a content detector is intuitive and widely adopted. Measured directly, the layers behave unevenly: tool authorization contributes a real and explicable gain; provenance contributes nothing over a low-recall lexical detector, appears strongly beneficial under an oracle, and is actively harmful over a realistic probabilistic detector. Detection recall dominated every policy mechanism we tested.

The most transferable result is methodological. Oracle-based evaluation of layered defenses is not conservative — it is biased in a specific direction, favoring exactly the layers whose costs manifest as false positives.

---

## Reproducibility

```bash
pip install -r requirements-dev.txt -r requirements-ml.txt -r scripts/requirements.txt
python scripts/build_eval_dataset.py      # 744 text examples
python scripts/build_agent_traces_v2.py   # 170 agent traces, held-out payloads
python scripts/train_ml_detector.py       # seeded 60/20/20, trains classifier
python scripts/compare_baselines.py       # §5.1 head-to-head
python scripts/run_ablation.py            # §5.3 all 11 configurations
python scripts/statistical_validation.py  # §5.2 seeds, McNemar, bootstrap CIs
pytest tests/ -q                          # 197 tests
```

Seed `20260903`; splits recorded in `dataset/processed/splits.json`.
