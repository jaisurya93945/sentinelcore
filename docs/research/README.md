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
