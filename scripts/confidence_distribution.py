"""
Tests the MECHANISM behind the provenance findings.

The claim (docs/paper/DRAFT.md section 5.4) is that provenance-aware policy acts
only on findings in the AMBIGUOUS confidence band: a finding confident
enough to block on its own leaves provenance nothing to add, and a
detector that produces no finding leaves it nothing to weight.

That predicts something specific and checkable: the semantic detector,
whose provenance gain was only +1.2pp, should produce FEWER ambiguous
findings than the learned classifier, whose gain was +11.8pp. If instead
the semantic detector produces plenty of ambiguous findings and provenance
still does nothing, the mechanism is wrong.

Reads existing result files. Makes no API calls and costs nothing.

Usage: python scripts/confidence_distribution.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

ROOT = Path(__file__).parent.parent
SEMANTIC = ROOT / "dataset" / "processed" / "semantic_results.json"
SPLITS = ROOT / "dataset" / "processed" / "splits.json"
EVAL = ROOT / "dataset" / "processed" / "eval_set.jsonl"
OUT = ROOT / "dataset" / "processed" / "confidence_distribution.json"

FLOOR, HIGH = 0.50, 0.80


def bands(probs):
    """Only probabilities at or above the reporting floor produce a
    finding at all. Of those, MEDIUM is the band provenance can act on."""
    reported = [p for p in probs if p >= FLOOR]
    medium = [p for p in reported if p < HIGH]
    high = [p for p in reported if p >= HIGH]
    return {
        "n_scored": len(probs),
        "n_reported": len(reported),
        "n_ambiguous_medium": len(medium),
        "n_confident_high": len(high),
        "ambiguous_share_of_findings": round(len(medium) / len(reported), 4) if reported else 0.0,
    }


def main():
    if not SEMANTIC.exists():
        print(f"Missing {SEMANTIC}. Run scripts/run_semantic_experiment.py first.")
        sys.exit(1)

    sem = json.loads(SEMANTIC.read_text())
    sem_probs = [r["p"] for r in sem["probabilities"]]

    # Learned classifier on the identical texts, for a like-for-like
    # comparison of confidence shape rather than of accuracy.
    import joblib

    recs = {json.loads(l)["id"]: json.loads(l) for l in EVAL.read_text(encoding="utf-8").splitlines() if l.strip()}
    ids = [r["id"] for r in sem["probabilities"]]
    texts = [recs[i]["text"] for i in ids]
    model = joblib.load(ROOT / "dataset" / "processed" / "ml_detector.joblib")
    ml_probs = list(model.predict_proba(texts)[:, 1])

    result = {
        "n": len(ids),
        "semantic": bands(sem_probs),
        "learned": bands(ml_probs),
        "observed_provenance_gain_pp": {"semantic_L_to_M": 1.2, "learned_J_to_K": 11.8},
    }
    OUT.write_text(json.dumps(result, indent=2))

    print(f"Confidence distribution on the same {len(ids)} held-out texts\n")
    print(f"{'':<28}{'semantic':>12}{'learned':>12}")
    for label, key in [("findings reported", "n_reported"),
                       ("  ambiguous (0.50-0.80)", "n_ambiguous_medium"),
                       ("  confident (>=0.80)", "n_confident_high")]:
        print(f"{label:<28}{result['semantic'][key]:>12}{result['learned'][key]:>12}")
    s = result["semantic"]["ambiguous_share_of_findings"]
    l = result["learned"]["ambiguous_share_of_findings"]
    print(f"{'ambiguous share of findings':<28}{s:>11.1%}{l:>12.1%}")

    print(f"\nobserved provenance gain:   semantic +1.2pp    learned +11.8pp")
    print("\nMechanism predicts the detector with the SMALLER ambiguous share")
    print("should show the SMALLER provenance gain.")
    if s < l:
        print(f"  -> CONSISTENT: semantic has the smaller ambiguous share ({s:.1%} < {l:.1%})")
        print("     and the smaller provenance gain (+1.2pp < +11.8pp).")
    else:
        print(f"  -> INCONSISTENT: semantic's ambiguous share ({s:.1%}) is NOT smaller")
        print("     than the learned classifier's, yet its provenance gain is.")
        print("     The mechanism in paper section 5.4 does not explain this and must be revised.")
    print(f"\nwritten to {OUT}")


if __name__ == "__main__":
    main()
