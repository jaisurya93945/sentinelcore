"""
Multi-seed threshold study.

Closes an item explicitly deferred in docs/research/README.md: a single
held-out slice showed the classifier reaching 0% FPR at threshold ~0.8,
but tuning production defaults on one slice is the error this project has
already had to correct twice. This repeats the analysis across seeds under
a protocol that cannot leak test data into the threshold choice.

PROTOCOL
For each seed:
  1. Split 60/20/20 stratified.
  2. Fit on train.
  3. Select thresholds on VALIDATION only:
       - t_zero_fp : lowest threshold achieving 0 false positives
       - t_f1      : threshold maximising F1
  4. Evaluate both on TEST, which is untouched until this point.

Reporting the spread of the SELECTED THRESHOLDS matters as much as the
resulting scores: if the chosen threshold swings wildly across seeds, no
single shipped default is defensible regardless of its mean performance.

Usage: python scripts/threshold_study.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline

from app.detectors.registry import get_registered_detectors  # noqa: E402

ROOT = Path(__file__).parent.parent
EVAL = ROOT / "dataset" / "processed" / "eval_set.jsonl"
OUT = ROOT / "dataset" / "processed" / "threshold_study.json"
BASE_SEED = 20260903
N_SEEDS = 10
GRID = np.round(np.arange(0.05, 1.00, 0.01), 2)


def build_pipeline(seed):
    features = FeatureUnion([
        ("word", TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True, lowercase=True)),
        ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, sublinear_tf=True)),
    ])
    clf = CalibratedClassifierCV(
        LogisticRegression(max_iter=2000, class_weight="balanced", random_state=seed), method="sigmoid", cv=5
    )
    return Pipeline([("features", features), ("clf", clf)])


def confusion(y, pred):
    y, pred = np.asarray(y), np.asarray(pred)
    return (int(((pred == 1) & (y == 1)).sum()), int(((pred == 1) & (y == 0)).sum()),
            int(((pred == 0) & (y == 0)).sum()), int(((pred == 0) & (y == 1)).sum()))


def scores(y, proba, t):
    tp, fp, tn, fn = confusion(y, (np.asarray(proba) >= t).astype(int))
    return {
        "threshold": float(t),
        "precision": tp / (tp + fp) if (tp + fp) else 1.0,
        "recall": tp / (tp + fn) if (tp + fn) else 0.0,
        "fpr": fp / (fp + tn) if (fp + tn) else 0.0,
        "f1": (2 * tp / (2 * tp + fp + fn)) if (2 * tp + fp + fn) else 0.0,
    }


def ci(vals):
    a = np.asarray(vals, dtype=float)
    lo, hi = np.percentile(a, [2.5, 97.5])
    return {"mean": round(float(a.mean()), 4), "std": round(float(a.std(ddof=1)), 4),
            "min": round(float(a.min()), 4), "max": round(float(a.max()), 4),
            "ci95": [round(float(lo), 4), round(float(hi), 4)]}


def main():
    recs = [json.loads(l) for l in EVAL.read_text(encoding="utf-8").splitlines() if l.strip()]
    X = [r["text"] for r in recs]
    y = [1 if r["label"] == "malicious" else 0 for r in recs]

    rules = {k: v for k, v in get_registered_detectors().items() if k != "ml_classifier"}

    picked_zero, picked_f1 = [], []
    test_zero, test_f1, test_fixed08, rules_test = [], [], [], []

    print(f"{'seed':>10}{'t_0fp':>8}{'t_f1':>8}   test@t_0fp (R/FPR)   test@0.80 (R/FPR)   rules (R/FPR)")
    for i in range(N_SEEDS):
        seed = BASE_SEED + i
        X_tr, X_tmp, y_tr, y_tmp = train_test_split(X, y, test_size=0.4, stratify=y, random_state=seed)
        X_va, X_te, y_va, y_te = train_test_split(X_tmp, y_tmp, test_size=0.5, stratify=y_tmp, random_state=seed)

        pipe = build_pipeline(seed).fit(X_tr, y_tr)
        p_va, p_te = pipe.predict_proba(X_va)[:, 1], pipe.predict_proba(X_te)[:, 1]

        # --- selection on VALIDATION only ---
        zero = [t for t in GRID if scores(y_va, p_va, t)["fpr"] == 0.0]
        t_zero = float(min(zero)) if zero else 1.0
        t_best_f1 = float(max(GRID, key=lambda t: scores(y_va, p_va, t)["f1"]))

        picked_zero.append(t_zero)
        picked_f1.append(t_best_f1)

        # --- evaluation on TEST ---
        sz, sf, s08 = scores(y_te, p_te, t_zero), scores(y_te, p_te, t_best_f1), scores(y_te, p_te, 0.80)
        test_zero.append(sz); test_f1.append(sf); test_fixed08.append(s08)

        r_pred = [int(any(len(c().detect(t)) > 0 for c in rules.values())) for t in X_te]
        tp, fp, tn, fn = confusion(y_te, r_pred)
        rules_test.append({"recall": tp / (tp + fn) if (tp + fn) else 0.0,
                           "fpr": fp / (fp + tn) if (fp + tn) else 0.0})

        print(f"{seed:>10}{t_zero:>8.2f}{t_best_f1:>8.2f}"
              f"{sz['recall']:>13.1%}/{sz['fpr']:.1%}{s08['recall']:>13.1%}/{s08['fpr']:.1%}"
              f"{rules_test[-1]['recall']:>10.1%}/{rules_test[-1]['fpr']:.1%}")

    result = {
        "n_seeds": N_SEEDS, "protocol": "threshold selected on validation, evaluated on test",
        "selected_threshold_zero_fp": ci(picked_zero),
        "selected_threshold_max_f1": ci(picked_f1),
        "test_at_selected_zero_fp": {k: ci([s[k] for s in test_zero]) for k in ("recall", "fpr", "precision")},
        "test_at_selected_max_f1": {k: ci([s[k] for s in test_f1]) for k in ("recall", "fpr", "precision")},
        "test_at_fixed_0.80": {k: ci([s[k] for s in test_fixed08]) for k in ("recall", "fpr", "precision")},
        "rules_baseline_test": {k: ci([s[k] for s in rules_test]) for k in ("recall", "fpr")},
    }
    OUT.write_text(json.dumps(result, indent=2))

    tz, tf = result["selected_threshold_zero_fp"], result["selected_threshold_max_f1"]
    print(f"\nselected threshold, zero-FP criterion: mean {tz['mean']:.2f} "
          f"[{tz['min']:.2f}-{tz['max']:.2f}]  std {tz['std']:.3f}")
    print(f"selected threshold, max-F1 criterion : mean {tf['mean']:.2f} "
          f"[{tf['min']:.2f}-{tf['max']:.2f}]  std {tf['std']:.3f}")

    for label, key in [("at validation-selected zero-FP threshold", "test_at_selected_zero_fp"),
                       ("at validation-selected max-F1 threshold", "test_at_selected_max_f1"),
                       ("at fixed 0.80", "test_at_fixed_0.80")]:
        r, f = result[key]["recall"], result[key]["fpr"]
        print(f"\nTEST {label}:")
        print(f"  recall {r['mean']:.1%} [{r['ci95'][0]:.1%},{r['ci95'][1]:.1%}]   "
              f"fpr {f['mean']:.1%} [{f['ci95'][0]:.1%},{f['ci95'][1]:.1%}]")

    rb = result["rules_baseline_test"]
    print(f"\nRULES baseline on same test splits:")
    print(f"  recall {rb['recall']['mean']:.1%} [{rb['recall']['ci95'][0]:.1%},{rb['recall']['ci95'][1]:.1%}]   "
          f"fpr {rb['fpr']['mean']:.1%} [{rb['fpr']['ci95'][0]:.1%},{rb['fpr']['ci95'][1]:.1%}]")
    print(f"\nwritten to {OUT}")


if __name__ == "__main__":
    main()
