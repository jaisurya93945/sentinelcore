"""
Statistical validation of the results in docs/paper/DRAFT.md.

Addresses the limitation the draft itself lists third: "no confidence
intervals or significance testing; single seed. Differences of a few
points should not be over-read." This script determines which reported
differences survive that scrutiny and which do not.

Three analyses:

  1. MULTI-SEED CLASSIFIER PERFORMANCE
     Retrain over N independent stratified splits. Reports mean and 95%
     CI for precision/recall/F1/FPR, so single-split luck is visible.

  2. McNEMAR'S EXACT TEST (rules vs learned)
     The correct paired test for two classifiers on the SAME test set.
     Unpaired t-tests would be wrong here: the same examples are scored
     by both systems, so the samples are not independent.

  3. BOOTSTRAP CIs FOR THE AGENT BENCHMARK
     APR/BCR on 22 attack and 15 benign traces. With n this small the
     intervals will be wide, and that is the point: it establishes
     whether the ablation's 9.1pp differences are distinguishable from
     noise or not. If they are not, the paper must say so.

Usage: python scripts/statistical_validation.py
"""

import json
import random
import sys
from math import comb
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline

from sentinelcore.detectors.registry import get_registered_detectors  # noqa: E402

ROOT = Path(__file__).parent.parent
OUT = ROOT / "dataset" / "processed" / "statistical_validation.json"
N_SEEDS = 10
N_BOOTSTRAP = 10000
BASE_SEED = 20260903


def build_pipeline(seed: int) -> Pipeline:
    features = FeatureUnion([
        ("word", TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True, lowercase=True)),
        ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, sublinear_tf=True)),
    ])
    clf = CalibratedClassifierCV(
        LogisticRegression(max_iter=2000, class_weight="balanced", random_state=seed), method="sigmoid", cv=5
    )
    return Pipeline([("features", features), ("clf", clf)])


def score(y_true, y_pred):
    tp = sum(1 for a, b in zip(y_true, y_pred) if a == 1 and b == 1)
    fp = sum(1 for a, b in zip(y_true, y_pred) if a == 0 and b == 1)
    tn = sum(1 for a, b in zip(y_true, y_pred) if a == 0 and b == 0)
    fn = sum(1 for a, b in zip(y_true, y_pred) if a == 1 and b == 0)
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    return {
        "precision": p,
        "recall": r,
        "f1": 2 * p * r / (p + r) if (p + r) else 0.0,
        "fpr": fp / (fp + tn) if (fp + tn) else 0.0,
    }


def ci95(values):
    a = np.array(values, dtype=float)
    lo, hi = np.percentile(a, [2.5, 97.5])
    return {"mean": round(float(a.mean()), 4), "std": round(float(a.std(ddof=1)), 4),
            "ci95_low": round(float(lo), 4), "ci95_high": round(float(hi), 4)}


def mcnemar_exact(b: int, c: int) -> float:
    """Exact two-sided McNemar. b = rules-only-correct, c = learned-only-correct.
    Under H0 each discordant pair is a fair coin flip."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = sum(comb(n, i) for i in range(0, k + 1)) / (2 ** n)
    return min(1.0, 2 * tail)


def bootstrap_rate(successes: int, total: int, rng: random.Random):
    """Bootstrap CI for a binary rate over `total` trials."""
    data = [1] * successes + [0] * (total - successes)
    rates = []
    for _ in range(N_BOOTSTRAP):
        rates.append(sum(rng.choices(data, k=total)) / total)
    a = np.array(rates)
    lo, hi = np.percentile(a, [2.5, 97.5])
    return {"point": round(successes / total, 4), "ci95_low": round(float(lo), 4), "ci95_high": round(float(hi), 4)}


def main():
    records = [json.loads(l) for l in (ROOT / "dataset/processed/eval_set.jsonl").read_text().splitlines() if l.strip()]
    X = [r["text"] for r in records]
    y = [1 if r["label"] == "malicious" else 0 for r in records]

    rules = {k: v for k, v in get_registered_detectors().items() if k != "ml_classifier"}

    # ---- 1. multi-seed ----
    print(f"Training across {N_SEEDS} independent splits...")
    per_seed = {"learned": [], "rules": []}
    mcnemar_pairs = []

    for i in range(N_SEEDS):
        seed = BASE_SEED + i
        X_tr, X_tmp, y_tr, y_tmp = train_test_split(X, y, test_size=0.4, stratify=y, random_state=seed)
        _, X_te, _, y_te = train_test_split(X_tmp, y_tmp, test_size=0.5, stratify=y_tmp, random_state=seed)

        pipe = build_pipeline(seed).fit(X_tr, y_tr)
        ml_pred = (pipe.predict_proba(X_te)[:, 1] >= 0.5).astype(int).tolist()
        rules_pred = [int(any(len(c().detect(t)) > 0 for c in rules.values())) for t in X_te]

        per_seed["learned"].append(score(y_te, ml_pred))
        per_seed["rules"].append(score(y_te, rules_pred))

        b = sum(1 for t, r_, m in zip(y_te, rules_pred, ml_pred) if r_ == t and m != t)
        c = sum(1 for t, r_, m in zip(y_te, rules_pred, ml_pred) if m == t and r_ != t)
        mcnemar_pairs.append({"seed": seed, "rules_only_correct": b, "learned_only_correct": c,
                              "p_value": mcnemar_exact(b, c)})
        print(f"  seed {seed}: learned R={per_seed['learned'][-1]['recall']:.3f}  "
              f"rules R={per_seed['rules'][-1]['recall']:.3f}  McNemar p={mcnemar_pairs[-1]['p_value']:.2e}")

    agg = {sys_: {m: ci95([s[m] for s in runs]) for m in ("precision", "recall", "f1", "fpr")}
           for sys_, runs in per_seed.items()}

    # ---- 3. bootstrap on agent traces ----
    rng = random.Random(BASE_SEED)
    _v2 = ROOT / "dataset/processed/ablation_results_v2.json"
    ab_path = _v2 if _v2.exists() else ROOT / "dataset/processed/ablation_results.json"
    print(f"\n(agent bootstrap using {ab_path.name})")
    ab = json.loads(ab_path.read_text())["summary"]
    boot = {}
    for cfg, r in ab.items():
        boot[cfg] = {
            "APR": bootstrap_rate(r["attacks_prevented"], r["attacks_total"], rng),
            "BCR": bootstrap_rate(r["benign_completed"], r["benign_total"], rng),
        }

    result = {
        "n_seeds": N_SEEDS, "n_bootstrap": N_BOOTSTRAP, "base_seed": BASE_SEED,
        "multi_seed": agg, "per_seed": per_seed, "mcnemar": mcnemar_pairs,
        "agent_bootstrap": boot,
    }
    OUT.write_text(json.dumps(result, indent=2))

    print(f"\n--- classifier vs rules, {N_SEEDS} seeds (mean [95% CI]) ---")
    for m in ("precision", "recall", "f1", "fpr"):
        r_, l_ = agg["rules"][m], agg["learned"][m]
        print(f"{m:<10} rules {r_['mean']:.3f} [{r_['ci95_low']:.3f},{r_['ci95_high']:.3f}]   "
              f"learned {l_['mean']:.3f} [{l_['ci95_low']:.3f},{l_['ci95_high']:.3f}]")

    ps = [m["p_value"] for m in mcnemar_pairs]
    print(f"\nMcNemar exact: max p across seeds = {max(ps):.2e}  "
          f"({sum(1 for p in ps if p < 0.05)}/{N_SEEDS} seeds significant at 0.05)")

    _any = next(iter(ab.values()))
    print(f"\n--- agent benchmark, bootstrap 95% CIs "
          f"(n={_any['attacks_total']} attack / {_any['benign_total']} benign) ---")
    for cfg in ("A_content_only", "B_prov_scoring", "C_tool_authz", "E_prov_rules", "H_oracleMED_flat", "I_oracleMED_prov", "J_ml_flat", "K_ml_prov"):
        a, bb = boot[cfg]["APR"], boot[cfg]["BCR"]
        print(f"{cfg:<20} APR {a['point']:.3f} [{a['ci95_low']:.3f},{a['ci95_high']:.3f}]   "
              f"BCR {bb['point']:.3f} [{bb['ci95_low']:.3f},{bb['ci95_high']:.3f}]")

    print(f"\nwritten to {OUT}")


if __name__ == "__main__":
    main()
