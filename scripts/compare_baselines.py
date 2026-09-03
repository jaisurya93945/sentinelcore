"""
Head-to-head baseline comparison on the IDENTICAL held-out test split.

Exists because of a methodological error caught during paper drafting:
the rules baseline had been quoted at 17.68% recall (measured on all 744
examples) against the classifier's 85.51% (measured on the 149-example
held-out split). Those are different datasets and the comparison was
invalid. On the same split the rules baseline scores 27.54%, so the real
improvement is 3.1x rather than the 4.8x originally claimed.

Usage: python scripts/compare_baselines.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.detectors.registry import get_registered_detectors  # noqa: E402

ROOT = Path(__file__).parent.parent
OUT = ROOT / "dataset" / "processed" / "baseline_comparison.json"


def metrics(tp, fp, tn, fn):
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    return {
        "precision": round(p, 4),
        "recall": round(r, 4),
        "f1": round(2 * p * r / (p + r), 4) if (p + r) else 0.0,
        "fpr": round(fp / (fp + tn), 4) if (fp + tn) else 0.0,
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
    }


def main():
    recs = {json.loads(l)["id"]: json.loads(l) for l in (ROOT / "dataset/processed/eval_set.jsonl").read_text().splitlines() if l.strip()}
    test_ids = json.loads((ROOT / "dataset/processed/splits.json").read_text())["test"]
    test = [recs[i] for i in test_ids]

    rules = {k: v for k, v in get_registered_detectors().items() if k != "ml_classifier"}
    c = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    for r in test:
        hit = any(len(cls().detect(r["text"])) > 0 for cls in rules.values())
        mal = r["label"] == "malicious"
        c["tp" if (hit and mal) else "fn" if mal else "fp" if hit else "tn"] += 1
    rules_m = metrics(**c)

    import joblib

    model = joblib.load(ROOT / "dataset/processed/ml_detector.joblib")
    proba = model.predict_proba([r["text"] for r in test])[:, 1]
    c2 = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    for r, p in zip(test, proba):
        hit = p >= 0.5
        mal = r["label"] == "malicious"
        c2["tp" if (hit and mal) else "fn" if mal else "fp" if hit else "tn"] += 1
    ml_m = metrics(**c2)

    result = {"split": "held-out test", "n": len(test), "rules_baseline": rules_m, "learned_classifier": ml_m}
    OUT.write_text(json.dumps(result, indent=2))

    print(f"Held-out test split, n={len(test)} -- identical data for both systems\n")
    print(f"{'':<22}{'rules':>10}{'learned':>10}")
    for k in ("precision", "recall", "f1", "fpr"):
        print(f"{k:<22}{rules_m[k]:>9.2%}{ml_m[k]:>10.2%}")
    print(f"\nrecall improvement: {ml_m['recall'] / rules_m['recall']:.2f}x")
    print(f"written to {OUT}")


if __name__ == "__main__":
    main()
