"""
Trains a learned prompt-injection classifier on the 744-example dataset.

WHY THIS EXISTS
Finding 4 predicted that provenance-aware policy only matters when
detection produces abundant *ambiguous* signal. That was demonstrated with
a ground-truth oracle, which is a simulation. This replaces the oracle
with a real detector that genuinely produces graded confidence, testing
the prediction outside simulation -- and it runs entirely offline, with no
model API required.

WHAT THIS IS, PRECISELY
TF-IDF (word + character n-grams) into a calibrated logistic regression.
It is a LEARNED LEXICAL classifier, NOT a transformer and NOT semantic
understanding. It generalises within vocabulary -- it can catch a
paraphrase that reuses known-suspicious words in an unseen arrangement --
but it will not understand a genuinely novel semantic attack, and it
inherits the language bias of the training data. Calling it "semantic"
would be false. What matters for the experiment is a property it
genuinely has and regex does not: it emits a probability rather than a
binary hit, so it can express uncertainty.

SPLIT DISCIPLINE
Stratified 60/20/20 train/validation/test, seeded. The test split is
touched exactly once, at the end, and is never used for threshold
selection -- that is what the validation split is for. This also closes a
gap flagged earlier in docs/research/README.md: the project previously had
no held-out set at all.

Usage: python scripts/train_ml_detector.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import joblib
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_recall_fscore_support, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline

ROOT = Path(__file__).parent.parent
DATASET = ROOT / "dataset" / "processed" / "eval_set.jsonl"
MODEL_OUT = ROOT / "dataset" / "processed" / "ml_detector.joblib"
SPLIT_OUT = ROOT / "dataset" / "processed" / "splits.json"
REPORT_OUT = ROOT / "dataset" / "processed" / "ml_detector_report.json"

SEED = 20260903


def main():
    records = [json.loads(l) for l in DATASET.read_text(encoding="utf-8").splitlines() if l.strip()]
    X = [r["text"] for r in records]
    y = [1 if r["label"] == "malicious" else 0 for r in records]
    ids = [r["id"] for r in records]

    # 60 / 20 / 20 stratified, seeded.
    X_tr, X_tmp, y_tr, y_tmp, id_tr, id_tmp = train_test_split(
        X, y, ids, test_size=0.4, stratify=y, random_state=SEED
    )
    X_val, X_te, y_val, y_te, id_val, id_te = train_test_split(
        X_tmp, y_tmp, id_tmp, test_size=0.5, stratify=y_tmp, random_state=SEED
    )

    SPLIT_OUT.write_text(json.dumps({"seed": SEED, "train": id_tr, "val": id_val, "test": id_te}, indent=2))

    features = FeatureUnion([
        ("word", TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True, lowercase=True)),
        # Character n-grams give partial robustness to spacing/obfuscation
        # tricks that break word tokenisation.
        ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, sublinear_tf=True)),
    ])

    # Calibrated so predict_proba is a usable confidence, not just a
    # ranking -- the whole experiment depends on graded confidence being
    # meaningful rather than arbitrary.
    clf = CalibratedClassifierCV(
        LogisticRegression(max_iter=2000, class_weight="balanced", random_state=SEED),
        method="sigmoid",
        cv=5,
    )
    pipe = Pipeline([("features", features), ("clf", clf)])
    pipe.fit(X_tr, y_tr)

    report = {"seed": SEED, "sizes": {"train": len(X_tr), "val": len(X_val), "test": len(X_te)}}

    for name, Xs, ys in [("validation", X_val, y_val), ("test_heldout", X_te, y_te)]:
        proba = pipe.predict_proba(Xs)[:, 1]
        pred = (proba >= 0.5).astype(int)
        p, r, f1, _ = precision_recall_fscore_support(ys, pred, average="binary", zero_division=0)
        tn = sum(1 for a, b in zip(ys, pred) if a == 0 and b == 0)
        fp = sum(1 for a, b in zip(ys, pred) if a == 0 and b == 1)
        report[name] = {
            "precision": round(float(p), 4),
            "recall": round(float(r), 4),
            "f1": round(float(f1), 4),
            "fpr": round(fp / (fp + tn), 4) if (fp + tn) else 0.0,
            "roc_auc": round(float(roc_auc_score(ys, proba)), 4),
        }

    # How much of the signal is genuinely AMBIGUOUS? This is the property
    # Finding 4 says provenance needs, so it is measured explicitly rather
    # than assumed.
    proba_test = pipe.predict_proba(X_te)[:, 1]
    bands = {
        "low_<0.35": int(sum(1 for p in proba_test if p < 0.35)),
        "ambiguous_0.35-0.70": int(sum(1 for p in proba_test if 0.35 <= p < 0.70)),
        "high_>=0.70": int(sum(1 for p in proba_test if p >= 0.70)),
    }
    report["confidence_distribution_test"] = bands

    joblib.dump(pipe, MODEL_OUT)
    REPORT_OUT.write_text(json.dumps(report, indent=2))

    print(f"train/val/test = {report['sizes']['train']}/{report['sizes']['val']}/{report['sizes']['test']}  seed={SEED}")
    for split in ("validation", "test_heldout"):
        m = report[split]
        print(f"{split:<14} P={m['precision']:.2%} R={m['recall']:.2%} F1={m['f1']:.2%} FPR={m['fpr']:.2%} AUC={m['roc_auc']:.3f}")
    print(f"\nconfidence bands on held-out test: {bands}")
    print(f"model -> {MODEL_OUT}")


if __name__ == "__main__":
    main()
