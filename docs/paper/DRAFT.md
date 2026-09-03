# When Does Provenance-Aware Policy Actually Help? An Ablation Study of Layered Defenses for LLM Agent Gateways

**DRAFT — not submitted.** Every number below is produced by a script in this repository and is reproducible from a clean checkout. Nothing is estimated. Where a result contradicts an earlier claim of ours, both are reported.

---

## Abstract

Defenses for LLM agents increasingly layer provenance tracking and authority enforcement on top of a content detector. We evaluate this layering directly, using an 11-configuration ablation over an agent-trace benchmark, and report three results that complicate the prevailing design.

First, **detection recall dominates**: replacing a hand-written rules detector with a learned classifier raises attack prevention from 81.8% to 100% on our benchmark, a larger gain than any policy mechanism we tested.

Second, **provenance-aware escalation is not free, and its measured value depends on how detection is simulated.** With a ground-truth oracle detector, adding provenance improves attack prevention by 9.1 points at zero utility cost. With a real classifier of comparable recall, the same mechanism yields no additional prevention and costs 20 points of benign task completion.

Third, and consequently, **oracle-based evaluation systematically overstates layered defenses.** An oracle has no false positives by construction; a layer whose cost is paid in escalated false positives therefore appears free. We argue this is a general hazard for evaluations of provenance and authority mechanisms, not a quirk of our system.

We also report a control-plane vulnerability class found in our own gateway: a component that correctly scanned tool calls was never reachable from the request path that produced them, so every model-generated action bypassed enforcement while each component passed its own tests.

---

## 1. Introduction

An LLM agent that retrieves documents, calls tools, and consumes MCP tool definitions has a substantially larger attack surface than a chat model. The dominant response is a layered gateway: detect suspicious content, attribute it to a provenance class, evaluate authority for the requested action, and enforce a decision.

Each layer is individually well-motivated. What is rarely measured is their **interaction** — specifically, whether a policy layer contributes anything once detection quality is held fixed, and whether its contribution survives realistic detector error.

We measure this with a deliberately unglamorous method: hold the benchmark fixed, vary one mechanism at a time, and report every configuration including the ones where our own mechanisms fail.

### Contributions

1. An 11-configuration ablation isolating content detection, provenance scoring, provenance-conditioned policy rules, tool authorization, and detector quality (§4).
2. A quantification of detection recall as the binding constraint: the entire 18.2-point prevention gap between our shipped system and an oracle is attributable to detection, not policy (§5.1).
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

**Agent-trace benchmark.** 37 deterministic event traces (22 attack, 15 benign) spanning direct injection, indirect injection via RAG, MCP tool poisoning, unauthorized tool use, exfiltration via tool arguments, and multi-step compositional attacks. Traces replay through the full pipeline.

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

**3.10× recall improvement**, at a real precision and false-positive cost.

*Correction:* an earlier draft of this work quoted 17.68% for the rules baseline — that figure is measured over all 744 examples, not the held-out split, and comparing it to the classifier's split-based 85.51% is invalid. On identical data the baseline scores 27.54%. The corrected improvement is 3.10×, not 4.84×.

### 5.2 Ablation

| Config | APR | BCR |
|---|---|---|
| A rules | 72.7% | 100.0% |
| B rules + prov. scoring | 72.7% | 100.0% |
| C rules + tool authz | 81.8% | 93.3% |
| D rules + scoring + authz | 81.8% | 93.3% |
| E rules + prov. rules + authz | 81.8% | 93.3% |
| F oracle(HIGH) | 100.0% | 93.3% |
| G oracle(HIGH) + prov. | 100.0% | 93.3% |
| H oracle(MED) | 81.8% | 93.3% |
| I oracle(MED) + prov. | **90.9%** | 93.3% |
| J learned | **100.0%** | 80.0% |
| K learned + prov. | 100.0% | **60.0%** |

**Tool authorization** contributes +9.1 APR (A→C), entirely within `compositional` and `unauthorized_tool` (both 75%→100%) — categories where the attack is a privileged action with clean arguments that no content scanner can see. It costs 6.7 BCR, traced to one identified scenario: a legitimate destructive operation blocked by policy.

**Provenance over rules-based detection contributes nothing** (A→B, C→D, D→E all null). Diagnosis: categorical per-type policy rules fire regardless of score, so score weighting never reaches a consulted threshold. Applying provenance at the *rule* layer instead (E) also changed zero of 37 decisions. Both null results have the same cause — the four attacks surviving every rules configuration produce **zero findings** (paraphrased, non-English, purely semantic, soft-phrased). Provenance re-weights findings that exist; zero multiplied by any trust factor is zero.

**Detection quality dominates.** J reaches 100% APR. The entire 18.2-point gap between C and J is detection, not policy.

### 5.3 The oracle inverts the provenance result

With an ambiguous-confidence oracle, provenance is a clean win: **H→I, +9.1 APR at zero BCR cost.**

With a real classifier of comparable recall, the same mechanism is a clear loss: **J→K, 0 APR gain, −20.0 BCR.**

The mechanism is visible in the failures. Under J, the classifier fires at ambiguous confidence on benign external content and the flat rule warns — harmless. Under K, the origin rule escalates that same uncertain finding to `block` because it arrived from `context`. Three ordinary workflows break: summarizing a quarterly report, an HR document lookup, a literature search.

**Provenance escalation converts a probabilistic detector's false positives into hard blocks.** A 5% FPR is tolerable when uncertainty only warns; it is not when provenance escalates uncertainty on external content — and in an agent system, most content is external.

The oracle has **zero false positives by construction**. That is precisely the assumption that fails in deployment, and precisely what made provenance appear free.

---

## 6. Discussion

**Provenance is not useless; its value is conditional.** It requires (a) a finding to exist, and (b) that finding to be genuinely ambiguous, and (c) the detector to be *precise within the ambiguous band*. Our oracle satisfied (c) by construction; our classifier does not.

**A methodological claim.** Any evaluation granting a defense ground-truth detection will overstate the value of layers built on top, because those layers' costs are paid in false positives an oracle cannot generate. Provenance and authority mechanisms are especially exposed, since their action is to *escalate*. We suggest such systems report utility under a realistic detector, not only attack success under a strong or oracle one.

**We acted on this internally:** the provenance-escalation rules for the learned detector are deliberately **not** in our shipped default policy, because our own experiment measured them as net-negative. They remain reproducible as an experimental override.

---

## 7. Limitations and Threats to Validity

1. **Self-authored agent benchmark.** 37 traces written by the same authors as the system. Mitigations: categories drawn from published taxonomies; nine scenarios deliberately included that the system is expected to fail; hard benign cases included so utility cost is measured. APR is 81.8%, not 100% — had it been 100%, the benchmark would be broken. This remains the most serious threat and is only fully addressed by external benchmarks (AgentDojo, InjecAgent), which we have not yet run.
2. **No live agent.** Deterministic trace replay, not a model-driven agent.
3. **Small scale.** 37 traces, 744 text examples, 149 held-out. No confidence intervals or significance testing; single seed. Differences of a few points should not be over-read.
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
python scripts/build_agent_traces.py      # 37 agent traces
python scripts/train_ml_detector.py       # seeded 60/20/20, trains classifier
python scripts/compare_baselines.py       # §5.1 head-to-head
python scripts/run_ablation.py            # §5.2 all 11 configurations
pytest tests/ -q                          # 197 tests
```

Seed `20260903`; splits recorded in `dataset/processed/splits.json`.
