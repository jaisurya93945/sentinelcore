"""
Cross-source generalization and operating-point analysis.

TWO QUESTIONS A REVIEWER ASKS BEFORE BELIEVING 0.884 RECALL

1. DOES IT TRANSFER?
   All reported performance so far comes from random splits of a pooled
   corpus. If the two source datasets share idiosyncrasies -- phrasing,
   collection method, annotation style -- a random split measures
   memorisation of those idiosyncrasies, not detection of prompt
   injection. The honest test is to train on one source and evaluate on
   the other, which no random split can simulate.

   deepset (662 examples, both classes) trains; pr1m8 (82 examples, all
   malicious, multilingual, categorised) is the transfer target. Because
   pr1m8 has no benign examples, this measures RECALL TRANSFER only --
   false-positive behaviour cannot be assessed on it, and we do not
   pretend otherwise.

2. WHAT IS THE OPERATING POINT COSTING?
   Everything so far is reported at threshold 0.5. That is an arbitrary
   default, and the interesting question for a deployment is the
   frontier: at the false-positive rate the rules baseline achieves, what
   recall does the classifier get? Reporting one point on a curve hides
   the trade-off the paper is actually about.

Usage: python scripts/cross_source_analysis.py
"""

import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_recall_curve, roc_curve
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline

from sentinelcore.detectors.registry import get_registered_detectors  # noqa: E402

ROOT = Path(__file__).parent.parent
EVAL = ROOT / "dataset" / "processed" / "eval_set.jsonl"
OUT = ROOT / "dataset" / "processed" / "cross_source_analysis.json"
SEED = 20260903


def build_pipeline(seed=SEED):
    features = FeatureUnion([
        ("word", TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True, lowercase=True)),
        ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, sublinear_tf=True)),
    ])
    clf = CalibratedClassifierCV(
        LogisticRegression(max_iter=2000, class_weight="balanced", random_state=seed), method="sigmoid", cv=5
    )
    return Pipeline([("features", features), ("clf", clf)])


def rules_hit(text: str) -> bool:
    dets = {k: v for k, v in get_registered_detectors().items() if k != "ml_classifier"}
    return any(len(c().detect(text)) > 0 for c in dets.values())


def main():
    records = [json.loads(l) for l in EVAL.read_text(encoding="utf-8").splitlines() if l.strip()]
    deepset = [r for r in records if r["id"].startswith("deepset-")]
    pr1m8 = [r for r in records if r["id"].startswith("pr1m8-")]

    result = {"seed": SEED, "deepset_n": len(deepset), "pr1m8_n": len(pr1m8)}

    # ---------- 1. cross-source transfer ----------
    X_tr = [r["text"] for r in deepset]
    y_tr = [1 if r["label"] == "malicious" else 0 for r in deepset]
    pipe = build_pipeline().fit(X_tr, y_tr)

    X_te = [r["text"] for r in pr1m8]
    proba = pipe.predict_proba(X_te)[:, 1]
    ml_hits = (proba >= 0.5).astype(int)
    rules_hits = np.array([int(rules_hit(t)) for t in X_te])

    # pr1m8 is all-malicious, so a "hit" is a true positive by definition.
    ml_recall = float(ml_hits.mean())
    rules_recall = float(rules_hits.mean())

    # in-domain reference on a held-out slice of deepset only
    Xa, Xb, ya, yb = train_test_split(X_tr, y_tr, test_size=0.25, stratify=y_tr, random_state=SEED)
    in_domain = build_pipeline().fit(Xa, ya)
    in_proba = in_domain.predict_proba(Xb)[:, 1]
    in_pred = (in_proba >= 0.5).astype(int)
    in_recall = float(np.mean([p for p, t in zip(in_pred, yb) if t == 1]))

    by_cat, by_lang = defaultdict(lambda: [0, 0]), defaultdict(lambda: [0, 0])
    for r, hit in zip(pr1m8, ml_hits):
        by_cat[r["category"] or "uncategorised"][0] += int(hit)
        by_cat[r["category"] or "uncategorised"][1] += 1
        by_lang[r.get("language", "unspecified")][0] += int(hit)
        by_lang[r.get("language", "unspecified")][1] += 1

    result["transfer"] = {
        "train": "deepset", "test": "pr1m8 (all malicious)",
        "in_domain_recall_reference": round(in_recall, 4),
        "cross_source_recall_learned": round(ml_recall, 4),
        "cross_source_recall_rules": round(rules_recall, 4),
        "by_category": {k: {"hit": v[0], "n": v[1], "recall": round(v[0] / v[1], 4)} for k, v in sorted(by_cat.items())},
        "by_language": {k: {"hit": v[0], "n": v[1], "recall": round(v[0] / v[1], 4)} for k, v in sorted(by_lang.items())},
    }

    # ---------- 2. operating-point frontier (in-domain, held-out) ----------
    prec, rec, pr_thresh = precision_recall_curve(yb, in_proba)
    fpr, tpr, roc_thresh = roc_curve(yb, in_proba)

    rules_pred_b = np.array([int(rules_hit(t)) for t in Xb])
    yb_arr = np.array(yb)
    r_tp = int(((rules_pred_b == 1) & (yb_arr == 1)).sum())
    r_fp = int(((rules_pred_b == 1) & (yb_arr == 0)).sum())
    r_fn = int(((rules_pred_b == 0) & (yb_arr == 1)).sum())
    r_tn = int(((rules_pred_b == 0) & (yb_arr == 0)).sum())
    rules_fpr = r_fp / (r_fp + r_tn) if (r_fp + r_tn) else 0.0
    rules_rec = r_tp / (r_tp + r_fn) if (r_tp + r_fn) else 0.0

    # What recall does the classifier reach at the rules baseline's FPR?
    # Take the BEST recall among points at or below the target FPR, not the
    # nearest FPR: roc_curve's first point is the degenerate (fpr=0, tpr=0,
    # threshold=inf) endpoint, and argmin-on-distance selects it whenever the
    # target FPR is 0, reporting 0% recall for a classifier that in fact
    # achieves 75.8% at that FPR.
    eligible = np.where(fpr <= rules_fpr + 1e-12)[0]
    idx = int(eligible[np.argmax(tpr[eligible])]) if len(eligible) else int(np.argmin(np.abs(fpr - rules_fpr)))
    matched = {
        "target_fpr_from_rules": round(rules_fpr, 4),
        "achieved_fpr": round(float(fpr[idx]), 4),
        "threshold": round(float(roc_thresh[idx]), 4),
        "learned_recall_at_that_fpr": round(float(tpr[idx]), 4),
        "rules_recall_for_comparison": round(rules_rec, 4),
    }

    points = []
    for t in (0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9):
        pred = (in_proba >= t).astype(int)
        tp = int(((pred == 1) & (yb_arr == 1)).sum()); fp = int(((pred == 1) & (yb_arr == 0)).sum())
        fn = int(((pred == 0) & (yb_arr == 1)).sum()); tn = int(((pred == 0) & (yb_arr == 0)).sum())
        points.append({
            "threshold": t,
            "precision": round(tp / (tp + fp), 4) if (tp + fp) else 0.0,
            "recall": round(tp / (tp + fn), 4) if (tp + fn) else 0.0,
            "fpr": round(fp / (fp + tn), 4) if (fp + tn) else 0.0,
        })

    result["operating_points"] = {"matched_fpr_comparison": matched, "sweep": points}
    OUT.write_text(json.dumps(result, indent=2))

    t = result["transfer"]
    print("=== 1. CROSS-SOURCE TRANSFER (train deepset -> test pr1m8) ===")
    print(f"  in-domain recall (deepset held-out):   {t['in_domain_recall_reference']:.1%}")
    print(f"  cross-source recall, learned:          {t['cross_source_recall_learned']:.1%}")
    print(f"  cross-source recall, rules baseline:   {t['cross_source_recall_rules']:.1%}")
    print(f"  transfer gap: {t['in_domain_recall_reference'] - t['cross_source_recall_learned']:+.1%}")
    print("\n  by language:")
    for k, v in t["by_language"].items():
        print(f"    {k:<14} {v['recall']:>6.1%}  ({v['hit']}/{v['n']})")
    print("\n  by attack category:")
    for k, v in t["by_category"].items():
        print(f"    {k:<24} {v['recall']:>6.1%}  ({v['hit']}/{v['n']})")

    m = matched
    print("\n=== 2. OPERATING POINTS (in-domain held-out) ===")
    print(f"  rules baseline: recall {m['rules_recall_for_comparison']:.1%} at FPR {m['target_fpr_from_rules']:.1%}")
    print(f"  learned at the SAME FPR ({m['achieved_fpr']:.1%}, thresh {m['threshold']:.2f}): "
          f"recall {m['learned_recall_at_that_fpr']:.1%}")
    print(f"\n  {'thresh':>7}{'prec':>9}{'recall':>9}{'fpr':>9}")
    for pt in points:
        print(f"  {pt['threshold']:>7.1f}{pt['precision']:>9.1%}{pt['recall']:>9.1%}{pt['fpr']:>9.1%}")
    print(f"\nwritten to {OUT}")


if __name__ == "__main__":
    main()
