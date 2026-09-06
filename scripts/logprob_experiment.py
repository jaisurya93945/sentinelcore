"""
Does reading confidence from token log-probabilities fix the quantisation
that disabled the policy layer?

THE QUESTION
Finding 8 measured that gpt-4o-mini's SELF-REPORTED probability takes 8
distinct values across 149 predictions, puts exactly one prediction in the
0.50-0.80 band, and gets 100% of its errors wrong confidently. A graded
policy layer built on that signal has nothing to act on (+1.2pp from
provenance, against +11.8pp for a calibrated classifier).

This asks whether that is a property of LLM DETECTION or merely of ASKING
THE MODEL TO STATE A NUMBER. Same model, same task, same texts -- the only
change is reading P(YES) out of the model's own token distribution instead
of its narration of it.

FALSIFICATION, RECORDED BEFORE RUNNING
If logprob confidence is also quantised into a handful of values and also
fails to populate the ambiguous band, then the limitation is LLM detection
itself and Finding 8 generalises. If it is continuous and better
calibrated, then Finding 8 is a finding about a common IMPLEMENTATION
CHOICE, not about language models -- a narrower claim, and the paper must
say so.

Either outcome is worth reporting. The second would be a correction to our
own framing, so it is named here in advance.

DESIGNED FOR A LOW DAILY QUOTA
--limit caps new calls per run. The distribution question is answerable on
a subset: 50 texts is enough to see whether the values are continuous or
snap to four round numbers. Run 50 first, look, and only spend the rest if
the answer is interesting.

    python scripts/logprob_experiment.py --limit 50      # one day at 50 RPD
    python scripts/logprob_experiment.py                 # resume; cached calls are free
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.config import settings  # noqa: E402
from app.detectors.semantic.detector import RateLimited, _cache_key, _cached, classify  # noqa: E402

ROOT = Path(__file__).parent.parent
EVAL = ROOT / "dataset" / "processed" / "eval_set.jsonl"
SPLITS = ROOT / "dataset" / "processed" / "splits.json"
VERBALIZED = ROOT / "dataset" / "processed" / "semantic_results.json"
OUT = ROOT / "dataset" / "processed" / "logprob_results.json"

FLOOR, HIGH = 0.50, 0.80


def profile(probs, labels):
    reported = [p for p in probs if p >= FLOOR]
    fn = [p for p, l in zip(probs, labels) if l == 1 and p < FLOOR]
    fp = [p for p, l in zip(probs, labels) if l == 0 and p >= FLOOR]
    confident_errors = sum(1 for p in fn if p <= 0.1) + sum(1 for p in fp if p >= 0.9)
    errors = len(fn) + len(fp)
    tp = sum(1 for p, l in zip(probs, labels) if l == 1 and p >= FLOOR)
    return {
        "n": len(probs),
        "distinct_values": len(set(round(p, 4) for p in probs)),
        "in_ambiguous_band": sum(1 for p in probs if FLOOR <= p < HIGH),
        "n_reported": len(reported),
        "precision": round(tp / len(reported), 4) if reported else 0.0,
        "recall": round(tp / max(1, sum(labels)), 4),
        "errors": errors,
        "confident_errors": confident_errors,
        "confident_error_share": round(confident_errors / errors, 4) if errors else 0.0,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0, help="cap NEW api calls this run (0 = no cap)")
    ap.add_argument("--estimate", action="store_true")
    args = ap.parse_args()

    recs = {json.loads(l)["id"]: json.loads(l) for l in EVAL.read_text(encoding="utf-8").splitlines() if l.strip()}
    test = [recs[i] for i in json.loads(SPLITS.read_text())["test"]]
    items = [(r["id"], r["text"], 1 if r["label"] == "malicious" else 0) for r in test]

    uncached = [t for _, t, _ in items if _cached(_cache_key(t, settings.semantic_model, "logprobs")) is None]
    print(f"texts: {len(items)}   already cached: {len(items) - len(uncached)}   to request: {len(uncached)}")
    print(f"at 50 req/day that is {(len(uncached) + 49) // 50} day(s); "
          f"the distribution question is answerable on ~50.\n")
    if args.estimate:
        return

    import os
    if not os.environ.get("OPENAI_API_KEY") and uncached:
        print("OPENAI_API_KEY not set and cache is incomplete.")
        sys.exit(1)

    probs, labels, new_calls, stopped = [], [], 0, False
    for i, (rid, text, label) in enumerate(items, 1):
        cached = _cached(_cache_key(text, settings.semantic_model, "logprobs"))
        if cached is None:
            if args.limit and new_calls >= args.limit:
                stopped = True
                break
            try:
                p = classify(text, mode="logprobs", raise_on_rate_limit=True)
            except RateLimited:
                print(f"  stopped at {i}/{len(items)}: rate limited. Cached work is preserved; re-run to resume.")
                stopped = True
                break
            if p is None:
                continue
            new_calls += 1
        else:
            p = cached
        probs.append(p)
        labels.append(label)
        if i % 25 == 0:
            print(f"  {i}/{len(items)}  (new calls: {new_calls})")

    if len(probs) < 25:
        print(f"\nOnly {len(probs)} results -- too few to judge the distribution. Re-run to collect more.")
        sys.exit(2)

    logprob_profile = profile(probs, labels)
    result = {"model": settings.semantic_model, "mode": "logprobs", "partial": stopped,
              "n_collected": len(probs), "new_api_calls_this_run": new_calls,
              "profile": logprob_profile,
              "value_counts": {str(k): v for k, v in sorted(Counter(round(p, 3) for p in probs).items())}}

    # Compare against the verbalized run on whatever overlap exists.
    if VERBALIZED.exists():
        v = json.loads(VERBALIZED.read_text())
        by_id = {r["id"]: r for r in v["probabilities"]}
        ids_collected = [rid for (rid, _, _), _ in zip(items, probs)]
        vp = [by_id[i]["p"] for i in ids_collected if i in by_id]
        vl = [by_id[i]["label"] for i in ids_collected if i in by_id]
        if len(vp) >= 25:
            result["verbalized_profile_same_texts"] = profile(vp, vl)

    OUT.write_text(json.dumps(result, indent=2))

    lp = logprob_profile
    print(f"\n=== LOGPROB CONFIDENCE (n={lp['n']}{', PARTIAL' if stopped else ''}) ===")
    vb = result.get("verbalized_profile_same_texts")
    hdr = f"{'':<26}{'logprobs':>11}" + (f"{'verbalized':>13}" if vb else "")
    print(hdr)
    for label, key in [("distinct values", "distinct_values"),
                       ("in 0.50-0.80 band", "in_ambiguous_band"),
                       ("errors", "errors"),
                       ("confident errors", "confident_errors")]:
        row = f"{label:<26}{lp[key]:>11}"
        if vb:
            row += f"{vb[key]:>13}"
        print(row)
    if vb:
        print(f"{'confident-error share':<26}{lp['confident_error_share']:>10.0%}{vb['confident_error_share']:>13.0%}")
        print(f"{'precision':<26}{lp['precision']:>10.1%}{vb['precision']:>13.1%}")
        print(f"{'recall':<26}{lp['recall']:>10.1%}{vb['recall']:>13.1%}")

    print("\nVERDICT")
    if lp["distinct_values"] >= 3 * max(1, (vb or lp)["distinct_values"]) and lp["in_ambiguous_band"] > (vb or lp)["in_ambiguous_band"]:
        print("  Logprob confidence is materially better distributed.")
        print("  => Finding 8 is about the verbalized-probability IMPLEMENTATION,")
        print("     not about LLM detection in general. The paper must narrow the claim.")
    elif lp["distinct_values"] <= 12 and lp["in_ambiguous_band"] <= 3:
        print("  Logprob confidence is ALSO quantised and also avoids the ambiguous band.")
        print("  => Finding 8 generalises beyond the implementation choice.")
    else:
        print("  Mixed. Report the numbers; do not force them into either conclusion.")
    print(f"\nwritten to {OUT}")


if __name__ == "__main__":
    main()
