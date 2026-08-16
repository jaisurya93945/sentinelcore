"""
Runs the full SentinelCore detection pipeline (detectors -> risk engine ->
policy engine) against dataset/processed/eval_set.jsonl and reports real,
reproducible precision/recall/F1/false-positive-rate. No hand-typed numbers
-- every figure in docs/research/ comes from this script.

Ground truth is binary (malicious/benign). A prediction counts as
"positive" (predicted malicious) if at least one detector produced a
finding -- this measures raw detection capability, independent of the
policy engine's block/warn/sanitize/allow choice (reported separately,
since it answers a different question: what would the gateway actually
DO, not just whether it noticed something).

Usage: python scripts/evaluate.py
"""

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.detectors.registry import get_registered_detectors  # noqa: E402
from app.services.policy_engine import decide  # noqa: E402
from app.services.risk_engine import calculate_risk_score  # noqa: E402

DATASET_PATH = Path(__file__).parent.parent / "dataset" / "processed" / "eval_set.jsonl"
RESULTS_PATH = Path(__file__).parent.parent / "dataset" / "processed" / "eval_results.json"


def load_dataset() -> list[dict]:
    with open(DATASET_PATH, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def run_pipeline(text: str):
    findings = []
    for cls in get_registered_detectors().values():
        findings.extend(cls().detect(text))
    score = calculate_risk_score(findings)
    decision = decide(findings, score)
    return findings, score, decision


def main():
    records = load_dataset()

    tp = fp = tn = fn = 0
    decision_on_malicious: Counter = Counter()
    decision_on_benign: Counter = Counter()
    category_recall: dict = defaultdict(lambda: {"total": 0, "caught": 0})
    language_recall: dict = defaultdict(lambda: {"total": 0, "caught": 0})
    false_negatives, false_positives = [], []

    for r in records:
        findings, score, decision = run_pipeline(r["text"])
        predicted_malicious = len(findings) > 0
        actual_malicious = r["label"] == "malicious"

        if actual_malicious and predicted_malicious:
            tp += 1
        elif actual_malicious and not predicted_malicious:
            fn += 1
            false_negatives.append({"id": r["id"], "text": r["text"][:120], "category": r["category"]})
        elif not actual_malicious and predicted_malicious:
            fp += 1
            false_positives.append({"id": r["id"], "text": r["text"][:120]})
        else:
            tn += 1

        if actual_malicious:
            decision_on_malicious[decision.value] += 1
            if r["category"]:
                category_recall[r["category"]]["total"] += 1
                category_recall[r["category"]]["caught"] += int(predicted_malicious)
            if r["language"]:
                language_recall[r["language"]]["total"] += 1
                language_recall[r["language"]]["caught"] += int(predicted_malicious)
        else:
            decision_on_benign[decision.value] += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    accuracy = (tp + tn) / len(records) if records else 0.0

    def with_recall(d: dict) -> dict:
        return {k: {**v, "recall": round(v["caught"] / v["total"], 4) if v["total"] else None} for k, v in sorted(d.items())}

    results = {
        "dataset_size": len(records),
        "malicious_count": tp + fn,
        "benign_count": tn + fp,
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "decision_distribution_on_malicious": dict(decision_on_malicious),
        "decision_distribution_on_benign": dict(decision_on_benign),
        "recall_by_category": with_recall(category_recall),
        "recall_by_language": with_recall(language_recall),
        "sample_false_negatives": false_negatives[:15],
        "sample_false_positives": false_positives[:15],
    }

    RESULTS_PATH.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"Dataset: {results['dataset_size']} examples ({results['malicious_count']} malicious, {results['benign_count']} benign)")
    print(f"Accuracy:  {results['accuracy']:.2%}")
    print(f"Precision: {results['precision']:.2%}")
    print(f"Recall:    {results['recall']:.2%}")
    print(f"F1:        {results['f1']:.2%}")
    print(f"FPR:       {results['false_positive_rate']:.2%}")
    print(f"\nFull results written to {RESULTS_PATH}")


if __name__ == "__main__":
    main()
