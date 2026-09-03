"""
Attack Replay Lab.

Snapshots evaluation results tagged by version, and compares any two
snapshots to show exactly what changed -- which specific attacks got
newly caught, which benign examples newly misfired, and how the headline
metrics moved. This is the regression/improvement tracking mechanism the
roadmap calls for: every version claim is backed by a diff against a
previous snapshot, not a re-typed number.

Usage:
    python scripts/replay_lab.py snapshot v0.1
    python scripts/replay_lab.py compare v0.1 v0.2
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.detectors.registry import get_registered_detectors  # noqa: E402

DATASET_PATH = Path(__file__).parent.parent / "dataset" / "processed" / "eval_set.jsonl"
SNAPSHOT_DIR = Path(__file__).parent.parent / "dataset" / "processed" / "replay_snapshots"


def load_dataset() -> list[dict]:
    with open(DATASET_PATH, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def run_detectors(text: str) -> list[str]:
    types = []
    for cls in get_registered_detectors().values():
        types.extend(f.type for f in cls().detect(text))
    return types


def snapshot(version: str) -> None:
    records = load_dataset()
    per_example = {}
    tp = fp = tn = fn = 0

    for r in records:
        finding_types = run_detectors(r["text"])
        predicted_malicious = len(finding_types) > 0
        actual_malicious = r["label"] == "malicious"
        per_example[r["id"]] = {
            "predicted_malicious": predicted_malicious,
            "actual_malicious": actual_malicious,
            "finding_types": finding_types,
        }
        if actual_malicious and predicted_malicious:
            tp += 1
        elif actual_malicious:
            fn += 1
        elif predicted_malicious:
            fp += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    result = {
        "version": version,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "dataset_size": len(records),
        "metrics": {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "false_positive_rate": round(fpr, 4),
            "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        },
        "per_example": per_example,
    }

    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = SNAPSHOT_DIR / f"{version}.json"
    out_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")

    m = result["metrics"]
    print(f"Snapshot '{version}' saved to {out_path}")
    print(f"  precision={m['precision']:.2%} recall={m['recall']:.2%} f1={m['f1']:.2%} fpr={m['false_positive_rate']:.2%}")


def compare(version_a: str, version_b: str) -> None:
    path_a = SNAPSHOT_DIR / f"{version_a}.json"
    path_b = SNAPSHOT_DIR / f"{version_b}.json"
    if not path_a.exists() or not path_b.exists():
        missing = version_a if not path_a.exists() else version_b
        print(f"No snapshot found for '{missing}'. Run: python scripts/replay_lab.py snapshot {missing}")
        sys.exit(1)

    a = json.loads(path_a.read_text(encoding="utf-8"))
    b = json.loads(path_b.read_text(encoding="utf-8"))

    print(f"=== {version_a} -> {version_b} ===\n")
    print(f"{'Metric':<22}{version_a:>10}{version_b:>10}{'Delta':>10}")
    for key in ["precision", "recall", "f1", "false_positive_rate"]:
        va, vb = a["metrics"][key], b["metrics"][key]
        print(f"{key:<22}{va:>10.2%}{vb:>10.2%}{vb - va:>+10.2%}")

    newly_caught, newly_missed, newly_broken, newly_fixed = [], [], [], []
    for ex_id, ex_a in a["per_example"].items():
        ex_b = b["per_example"].get(ex_id)
        if ex_b is None:
            continue
        if ex_a["actual_malicious"]:
            if not ex_a["predicted_malicious"] and ex_b["predicted_malicious"]:
                newly_caught.append(ex_id)
            elif ex_a["predicted_malicious"] and not ex_b["predicted_malicious"]:
                newly_missed.append(ex_id)
        else:
            if not ex_a["predicted_malicious"] and ex_b["predicted_malicious"]:
                newly_broken.append(ex_id)
            elif ex_a["predicted_malicious"] and not ex_b["predicted_malicious"]:
                newly_fixed.append(ex_id)

    print(f"\nNewly caught attacks:       {len(newly_caught)}")
    print(f"Newly missed (regression):  {len(newly_missed)}")
    print(f"Newly broken (new FPs):     {len(newly_broken)}")
    print(f"Newly fixed (FPs resolved): {len(newly_fixed)}")

    if newly_caught:
        print(f"\nNewly caught IDs: {newly_caught}")
    if newly_missed:
        print(f"\n/!\\ REGRESSION -- previously-caught attacks now missed: {newly_missed}")
    if newly_broken:
        print(f"\n/!\\ New false positives introduced: {newly_broken}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "snapshot" and len(sys.argv) == 3:
        snapshot(sys.argv[2])
    elif cmd == "compare" and len(sys.argv) == 4:
        compare(sys.argv[2], sys.argv[3])
    else:
        print(__doc__)
        sys.exit(1)
