"""Smoke test: the normalized evaluation dataset is well-formed and present.
Regenerate with `python scripts/build_eval_dataset.py` if this ever fails
because the file is missing."""

import json
from pathlib import Path

DATASET_PATH = Path(__file__).parent.parent.parent / "dataset" / "processed" / "eval_set.jsonl"


def test_eval_dataset_exists_and_is_well_formed():
    assert DATASET_PATH.exists(), "run `python scripts/build_eval_dataset.py` first"
    records = [json.loads(line) for line in DATASET_PATH.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(records) > 0
    labels = set()
    for r in records:
        assert r["label"] in {"malicious", "benign"}
        assert isinstance(r["text"], str) and r["text"]
        assert "id" in r and "source" in r
        labels.add(r["label"])
    assert labels == {"malicious", "benign"}, "dataset should contain both classes"
