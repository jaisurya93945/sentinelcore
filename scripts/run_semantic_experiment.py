"""
Turnkey semantic-detector experiment. RUN THIS ON A MACHINE WITH AN
OPENAI API KEY -- it cannot run in the development sandbox, where
api.openai.com is blocked at the network proxy (verified:
x-deny-reason: host_not_allowed).

    export OPENAI_API_KEY=sk-...
    pip install -r requirements-semantic.txt
    python scripts/run_semantic_experiment.py --estimate    # cost only, no spend
    python scripts/run_semantic_experiment.py               # run it

WHAT IT MEASURES
  1. Head-to-head detection on the SAME held-out split already used for
     the rules and learned detectors, so all three are comparable.
  2. The full agent-trace ablation with the semantic detector substituted
     in, giving configs L (semantic) and M (semantic + provenance).

THE PREDICTION, STATED BEFORE RUNNING
docs/paper/DRAFT.md argues provenance's value tracks detector
PRECISION-IN-THE-AMBIGUOUS-BAND, not detector strength. So a stronger
semantic detector should NOT automatically make provenance more valuable
-- it should move where the useful operating point sits. If instead the
provenance gain simply grows with detector quality, the paper's mechanism
is WRONG and must be rewritten. Both outcomes are reportable; record
whichever occurs.

Everything is cached to disk, so a re-run after the first costs nothing.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.config import settings  # noqa: E402
from app.detectors.semantic.detector import RateLimited, _cache_key, _cached, classify  # noqa: E402

ROOT = Path(__file__).parent.parent
EVAL = ROOT / "dataset" / "processed" / "eval_set.jsonl"
SPLITS = ROOT / "dataset" / "processed" / "splits.json"
TRACES = ROOT / "dataset" / "processed" / "agent_traces_v2.jsonl"
OUT = ROOT / "dataset" / "processed" / "semantic_results.json"

# gpt-4o-mini list pricing as of early 2026, USD per 1M tokens. Used only
# for a pre-flight estimate; verify against current pricing before relying
# on it.
PRICE_IN, PRICE_OUT = 0.15, 0.60


def collect_texts():
    recs = {json.loads(l)["id"]: json.loads(l) for l in EVAL.read_text(encoding="utf-8").splitlines() if l.strip()}
    test = [recs[i] for i in json.loads(SPLITS.read_text())["test"]]
    texts = [(r["id"], r["text"], 1 if r["label"] == "malicious" else 0) for r in test]

    trace_texts = []
    if TRACES.exists():
        for line in TRACES.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            s = json.loads(line)
            for ev in s["events"]:
                t = ev.get("text") or json.dumps(ev.get("arguments", {}))
                if t.strip():
                    trace_texts.append(t)
    return texts, trace_texts


def estimate(texts, trace_texts):
    all_t = [t for _, t, _ in texts] + trace_texts
    # Deduplicate before counting. The cache is keyed by text hash, so a
    # repeated string is a cache hit on its second occurrence and costs
    # nothing. Counting raw occurrences overstated the call count by 42%
    # in the first version of this script -- 441 reported against 255
    # actually required -- which matters a great deal to anyone working
    # under a low requests-per-day quota.
    unique = list(dict.fromkeys(all_t))
    uncached = [t for t in unique if _cached(_cache_key(t, settings.semantic_model)) is None]
    in_tok = sum(len(t) // 4 + 120 for t in uncached)  # ~4 chars/token + system prompt
    out_tok = 15 * len(uncached)
    cost = in_tok / 1e6 * PRICE_IN + out_tok / 1e6 * PRICE_OUT
    split_unique = len(dict.fromkeys(t for _, t, _ in texts))
    print(f"model:              {settings.semantic_model}")
    print(f"text occurrences:   {len(all_t)}")
    print(f"unique texts:       {len(unique)}  (duplicates are free -- cache is keyed by text)")
    print(f"already cached:     {len(unique) - len(uncached)}")
    print(f"TO BE REQUESTED:    {len(uncached)}")
    print(f"  of which held-out split (--texts-only): {split_unique} unique")
    print(f"est. input tok:   {in_tok:,}")
    print(f"est. output tok:  {out_tok:,}")
    print(f"ESTIMATED COST:     ${cost:.4f} USD")
    print("\n(list pricing; verify current rates. Cached calls cost nothing on re-run.)")
    for rpd in (50, 200, 500):
        days = (len(uncached) + rpd - 1) // rpd
        split_days = (split_unique + rpd - 1) // rpd
        print(f"  at {rpd:>3} req/day: {days} day(s) for everything, {split_days} for the split alone")
    return cost


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--estimate", action="store_true", help="print cost estimate and exit without spending")
    ap.add_argument("--limit", type=int, default=0,
                    help="stop after N NEW api calls this run (0 = no cap). Use to stay under a daily quota.")
    ap.add_argument("--texts-only", action="store_true",
                    help="classify only the held-out split (the headline detection result), skip trace warming")
    ap.add_argument("--delay", type=float, default=0.0,
                    help="seconds to sleep between new calls; use if hitting per-minute limits")
    args = ap.parse_args()

    texts, trace_texts = collect_texts()
    cost = estimate(texts, trace_texts)
    if args.estimate:
        return

    import os

    if not os.environ.get("OPENAI_API_KEY"):
        print("\nOPENAI_API_KEY is not set. Export it and re-run.")
        sys.exit(1)

    print(f"\nProceeding. Ctrl-C now to abort.\n")
    settings.semantic_detector_enabled = True

    import time as _time

    new_calls = 0
    quota_hit = False

    def _classify(text):
        """Returns (p, stop). Counts only NEW calls against --limit, since
        cache hits cost nothing and shouldn't consume the budget."""
        nonlocal new_calls, quota_hit
        cached = _cached(_cache_key(text, settings.semantic_model))
        if cached is not None:
            return cached, False
        if args.limit and new_calls >= args.limit:
            return None, True
        try:
            p = classify(text, raise_on_rate_limit=True)
        except RateLimited as e:
            if e.daily:
                quota_hit = True
                return None, True
            return None, True
        new_calls += 1
        if args.delay:
            _time.sleep(args.delay)
        return p, False

    # ---- 1. detection head-to-head on the held-out split ----
    print("Classifying held-out split...")
    tp = fp = tn = fn = 0
    probs = []
    missing = 0
    for i, (rid, text, label) in enumerate(texts, 1):
        p, stop = _classify(text)
        if stop:
            missing = len(texts) - i + 1
            break
        if p is None:
            missing += 1
            continue
        probs.append({"id": rid, "p": p, "label": label})
        hit = p >= 0.5
        if hit and label: tp += 1
        elif hit: fp += 1
        elif label: fn += 1
        else: tn += 1
        if i % 25 == 0:
            print(f"  {i}/{len(texts)}  (new api calls this run: {new_calls})")

    if missing:
        reason = "daily quota exhausted" if quota_hit else "run limit reached"
        print(f"\n  PARTIAL: {len(probs)}/{len(texts)} classified, {missing} outstanding ({reason}).")
        print(f"  Everything classified so far is CACHED -- re-running will not re-request it.")
        print(f"  Resume later with the same command; only the {missing} outstanding will be requested.")
        if len(probs) < 30:
            print("\n  Too few results to report meaningful metrics. Stopping.")
            sys.exit(2)
        print(f"  Reporting metrics on the {len(probs)} classified so far -- these are PARTIAL")
        print(f"  and not comparable to the full-split numbers until the run completes.")

    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    result = {
        "model": settings.semantic_model,
        "partial": bool(missing),
        "outstanding": missing,
        "new_api_calls_this_run": new_calls,
        "detection": {
            "n": len(probs), "precision": round(prec, 4), "recall": round(rec, 4),
            "f1": round(2 * prec * rec / (prec + rec), 4) if (prec + rec) else 0.0,
            "fpr": round(fp / (fp + tn), 4) if (fp + tn) else 0.0,
            "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        },
        "probabilities": probs,
        "estimated_cost_usd": round(cost, 4),
    }

    d = result["detection"]
    print(f"\n=== SEMANTIC DETECTOR on the same held-out split (n={d['n']}) ===")
    print(f"  precision {d['precision']:.2%}  recall {d['recall']:.2%}  f1 {d['f1']:.2%}  fpr {d['fpr']:.2%}")
    print("\n  compare (same split, from docs/research/README.md):")
    print("    rules baseline   recall 18.6% [12.2, 28.7]   fpr 0.5%")
    print("    learned @0.80    recall 72.0% [60.4, 83.7]   fpr 1.1%")

    # ---- 2. warm the cache for the agent traces ----
    if args.texts_only:
        print("\n--texts-only: skipping trace warming.")
    elif missing:
        print("\nSkipping trace warming: finish the held-out split first.")
    else:
        print(f"\nWarming cache for {len(trace_texts)} trace texts...")
        warmed_stop = False
        for i, t in enumerate(trace_texts, 1):
            _, stop = _classify(t)
            if stop:
                print(f"  stopped at {i}/{len(trace_texts)} -- cached so far is preserved; re-run to continue.")
                warmed_stop = True
                break
            if i % 50 == 0:
                print(f"  {i}/{len(trace_texts)}  (new api calls this run: {new_calls})")
        if not warmed_stop:
            print("  trace cache complete.")

    OUT.write_text(json.dumps(result, indent=2))
    print(f"\nwritten to {OUT}")
    print("\nNEXT: run the ablation with the semantic detector active:")
    print("  SENTINELCORE_SEMANTIC_DETECTOR_ENABLED=true python scripts/run_ablation.py")
    print("\nThen check the paper's prediction: did the provenance gain (J->K equivalent)")
    print("grow with detector strength, or stay tied to precision-in-the-ambiguous-band?")
    print("If it simply grew, docs/paper/DRAFT.md section 5.4 is wrong and must be rewritten.")


if __name__ == "__main__":
    main()
