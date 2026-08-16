"""
Normalizes raw external datasets into SentinelCore's unified evaluation
schema (dataset/processed/eval_set.jsonl). Run once after downloading raw
sources into dataset/raw/. See dataset/README.md for full attribution.

Usage: python scripts/build_eval_dataset.py
"""

import csv
import json
from pathlib import Path

import pandas as pd

RAW_DIR = Path(__file__).parent.parent / "dataset" / "raw"
OUT_PATH = Path(__file__).parent.parent / "dataset" / "processed" / "eval_set.jsonl"

# pr1m8 category -> SentinelCore's own finding-type taxonomy.
# Deliberately conservative: only mapped where the source category is a
# clear match for what a v0.1 detector actually targets. Unmapped
# categories are kept as-is, so recall on them can be honestly reported
# as "not yet covered" instead of silently dropped or force-mapped.
PR1M8_CATEGORY_MAP = {
    "Instruction Override": "instruction_override",
    "Role-Playing": "role_manipulation",
    "Jailbreak": "role_manipulation",
    "Formatting Trick": "obfuscation",
}


def normalize_pr1m8() -> list[dict]:
    path = RAW_DIR / "pr1m8_prompt_injections.csv"
    records = []
    with open(path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            records.append(
                {
                    "id": f"pr1m8-{row['id']}",
                    "text": row["text"],
                    "label": "malicious",
                    "category": PR1M8_CATEGORY_MAP.get(row["category"], row["category"]),
                    "source": "pr1m8/prompt-injections (github.com/pr1m8/prompt-injections, MIT)",
                    "language": row["language"],
                    "metadata": {
                        "original_category": row["category"],
                        "subcategory": row.get("subcategory", ""),
                    },
                }
            )
    return records


def normalize_deepset() -> list[dict]:
    records = []
    for split, filename in [("train", "deepset_train.parquet"), ("test", "deepset_test.parquet")]:
        df = pd.read_parquet(RAW_DIR / filename)
        for i, row in df.iterrows():
            records.append(
                {
                    "id": f"deepset-{split}-{i:04d}",
                    "text": row["text"],
                    "label": "malicious" if row["label"] == 1 else "benign",
                    "category": None,
                    "source": (
                        "deepset/prompt-injections "
                        "(mirrored via github.com/sinanw/llm-security-prompt-injection, MIT)"
                    ),
                    "language": "unspecified",  # source has no per-row language label
                    "metadata": {"split": split},
                }
            )
    return records


def main():
    records = normalize_pr1m8() + normalize_deepset()
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    malicious = sum(1 for r in records if r["label"] == "malicious")
    benign = sum(1 for r in records if r["label"] == "benign")
    print(f"Wrote {len(records)} examples to {OUT_PATH}")
    print(f"  malicious: {malicious}")
    print(f"  benign: {benign}")


if __name__ == "__main__":
    main()
