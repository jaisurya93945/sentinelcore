# Product roadmap — from working gateway to usable control plane

Prioritized against what exists today, verified against `docs/CAPABILITY_MATRIX.md` and the evidence audit. The research work validates the product; it does not replace it.

## Where the product actually is

**Real and tested:** a provider-agnostic reverse proxy with detection (rules + optional learned + optional semantic), risk scoring, policy enforcement, sanitization with re-scan, tool-call inspection with deterministic authorization, human approval with fail-closed expiry, RAG/context scanning with provenance tagging, MCP tool-definition scanning, metadata-only audit, a read-only dashboard, API-key auth with three roles, and rate limiting. 246 tests.

**The honest gap:** none of this is *installable*. There is no package, no SDK, no CLI, no deployment story beyond an untested Dockerfile. A developer cannot adopt SentinelCore today without cloning a research repository — which is the single largest obstacle between the current state and the stated goal.

---

## P0 — Make it adoptable  ·  **items 1–3 DONE**

Status as of `v0.4.0`: the package installs, imports, scans and ships a working CLI, verified in a clean virtualenv. Item 4 (a Dockerfile that has actually been built) remains open.


**1. Ship a real Python package. — DONE.** `pip install sentinelcore`. Proper `pyproject.toml` metadata, `py.typed`, semantic versioning, wheel + sdist, minimal mandatory dependencies with extras (`[ml]`, `[semantic]`, `[server]`). Verify in a clean venv: `pip install dist/*.whl && python -c "import sentinelcore"`. **Do not publish to PyPI without explicit authorization.**

**2. A stable public API — DONE.** Three integration shapes, because developers arrive with different constraints:

```python
from sentinelcore import Guard
guard = Guard(policy="balanced")

result = guard.scan(text, origin="input")          # library call
app.add_middleware(guard.middleware())             # FastAPI/ASGI middleware
# gateway: already exists as the reverse proxy
```

All three now exist. `sentinelcore.guard` is the public module; `sentinelcore.api` remains the internal HTTP layer.

**3. A CLI. — DONE.** `sentinel doctor` (config sanity), `sentinel scan <path>` (pre-deployment), `sentinel proxy`, `sentinel policy test`, `sentinel mcp scan`. Human-readable and `--json`, with meaningful exit codes so it works in CI.

**4. Docker that is actually built and tested.** The current Dockerfile has never been built — flagged in the file itself. Build it, smoke-test it, publish nothing until it passes.

## P1 — Close the loop developers expect

**5. Named policy presets.** `strict` / `balanced` / `permissive`, each with its measured operating point published from the ablation. The security/utility frontier is this project's most defensible result; presets are how it reaches a user. This is the product surface of Findings 5–9.

**6. Alerting.** The audit trail exists; nothing watches it. Webhook and Slack sinks on BLOCK/HUMAN_APPROVAL, plus a rate-of-change trigger. Without this, "continuous monitoring" is a dashboard someone has to remember to open.

**7. Dashboard beyond a live tail.** Decision-rate trends, top finding types, per-tool authorization outcomes, pending approvals, false-positive review queue. The FP review queue matters most: over-defense is the failure operators actually feel, and giving them a way to see and correct it is worth more than another detector.

**8. Persistence that survives production.** SQLite with no migrations, no retention, no rotation, and a synchronous connection per write. Needs schema versioning, indexes, retention policy, and a Postgres option.

## P2 — Pre-deployment and continuous surfaces

**9. Pre-deployment assessment.** `sentinel scan .` over a codebase and its configuration: system prompts, registered tools, MCP server definitions, RAG sources. Produces a report. This is the "before deployment" leg of the product diagram and is currently absent.

**10. Continuous monitoring.** Scheduled re-scan of MCP tool definitions with fingerprint pinning and change detection — a trusted tool whose description silently changes is a real, documented attack (rug-pull) and the current MCP scanning is one-shot.

**11. Multi-agent / multi-tenant.** Only after an identity model exists. Building tenant isolation without one produces unsafe partial isolation, which is worse than none.

## P3 — Research-dependent, deliberately last

**12. Stateful session security and the action graph.** Real, valuable, and correctly deferred: Findings 5–9 show the policy layer is bounded by detector signal quality. Adding session state on top of a detector whose confidence has no usable middle would optimise the layer that is not the bottleneck.

**13. Adaptive-attack evaluation.** Everything measured so far is against static corpora. No claim about robustness is currently supportable.

---

## The SLM question — evaluated, not assumed

**Recommendation: do not train one yet.** The evidence does not support it.

| Option | Accuracy | Calibration | Latency | Cost | Privacy | Verdict |
|---|---|---|---|---|---|---|
| Rules | recall 0.185 | n/a | µs | zero | local | Keep — high precision, catches obfuscation the classifier misses |
| **TF-IDF + logreg** | **recall 0.884** | **143 distinct values, 7% confident errors** | **ms** | **zero** | **local** | **Keep as default** |
| LLM semantic | recall 0.551 | **8 values, 100% confident errors** | ~1s | per-call | **egress** | Optional; best on tool arguments specifically |
| Fine-tuned SLM | unknown | unknown | ~10ms | GPU or CPU | local | **Unjustified today** |

The classifier already delivers the properties an SLM would be built for — local, fast, free, well-calibrated — at recall the LLM did not match. **An SLM becomes justified only if a measurement shows the classifier failing somewhere the SLM would plausibly succeed.** Two candidates exist: cross-lingual generalisation, and the `obfuscation` category where cross-source transfer measured only 50%. Neither has been tested against an SLM baseline, and both should be before any training run.

If one is eventually built, it belongs as **one detector behind the existing registry interface**, benchmarked against the TF-IDF baseline on the same held-out split — not as the product.

---

## Sequencing

P0 in full before P1. A control plane nobody can install is not a control plane, and every subsequent item is worth more once there is a real user surface to attach it to. P3 waits on evidence rather than ambition — which is the same discipline that produced the findings in the first place.
