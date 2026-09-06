"""
Head-to-head against a real industry guardrail: Meta Llama Prompt Guard 2.

WHY THIS IS THE MISSING EXPERIMENT
Every detection number in this project has been measured against our own
rules baseline. A reviewer's first question is "compared to what?" -- and
"compared to our own weaker thing" is not an answer. Prompt Guard 2 is the
right comparator: open weights, runs locally, no API key, no rate limit,
no per-request cost, and it is what a team would actually reach for.

RUN THIS ON YOUR MACHINE (the dev sandbox cannot reach huggingface.co).

    pip install -r requirements-industry.txt
    python scripts/benchmark_industry.py

First run downloads ~370MB (86M-parameter mDeBERTa). CPU inference is fine.

WHAT WE EXPECT, RECORDED BEFORE RUNNING
Published work reports lightweight n-gram classifiers outperforming
Prompt Guard 2 on held-out sets, and reports severe over-defense from
Prompt Guard on benign text containing attack vocabulary. If our
classifier wins here, that is a REPLICATION of a known result, not a
discovery, and the paper says so. If Prompt Guard wins, we report that
plainly and the paper's detector claims narrow accordingly.

Either way the comparison is the point. A security tool that has never
been measured against the incumbent has not been evaluated.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

ROOT = Path(__file__).parent.parent
EVAL = ROOT / "dataset" / "processed" / "eval_set.jsonl"
SPLITS = ROOT / "dataset" / "processed" / "splits.json"
OUT = ROOT / "dataset" / "processed" / "industry_comparison.json"

MODEL_ID = "meta-llama/Llama-Prompt-Guard-2-86M"
MAX_TOKENS = 512  # Prompt Guard 2's context window; longer inputs are chunked


def metrics(y_true, y_pred):
    tp = sum(1 for a, b in zip(y_true, y_pred) if a == 1 and b == 1)
    fp = sum(1 for a, b in zip(y_true, y_pred) if a == 0 and b == 1)
    tn = sum(1 for a, b in zip(y_true, y_pred) if a == 0 and b == 0)
    fn = sum(1 for a, b in zip(y_true, y_pred) if a == 1 and b == 0)
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    return {
        "precision": round(p, 4), "recall": round(r, 4),
        "f1": round(2 * p * r / (p + r), 4) if (p + r) else 0.0,
        "fpr": round(fp / (fp + tn), 4) if (fp + tn) else 0.0,
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
    }


def promptguard_scores(texts, threshold=0.5):
    """Max-score pooling over 512-token chunks, matching the protocol used
    in the published literature so our numbers are comparable to theirs."""
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    print(f"loading {MODEL_ID} (first run downloads ~370MB)...")
    tok = AutoTokenizer.from_pretrained(MODEL_ID)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_ID)
    model.eval()

    scores = []
    for i, text in enumerate(texts, 1):
        ids = tok(text, return_tensors="pt", truncation=False)["input_ids"][0]
        chunks = [ids[j:j + MAX_TOKENS] for j in range(0, max(1, len(ids)), MAX_TOKENS)] or [ids]
        best = 0.0
        for ch in chunks:
            with torch.no_grad():
                logits = model(input_ids=ch.unsqueeze(0)).logits
            best = max(best, float(torch.softmax(logits, dim=-1)[0][-1]))
        scores.append(best)
        if i % 25 == 0:
            print(f"  {i}/{len(texts)}")
    return scores


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--threshold", type=float, default=0.5)
    args = ap.parse_args()

    recs = {json.loads(l)["id"]: json.loads(l) for l in EVAL.read_text(encoding="utf-8").splitlines() if l.strip()}
    test = [recs[i] for i in json.loads(SPLITS.read_text())["test"]]
    texts = [r["text"] for r in test]
    y = [1 if r["label"] == "malicious" else 0 for r in test]

    print(f"held-out test split: n={len(texts)}\n")

    # --- incumbent ---
    pg_scores = promptguard_scores(texts, args.threshold)
    pg = metrics(y, [int(s >= args.threshold) for s in pg_scores])

    # --- ours ---
    import joblib
    from app.detectors.registry import get_registered_detectors

    model = joblib.load(ROOT / "dataset" / "processed" / "ml_detector.joblib")
    ours_p = list(model.predict_proba(texts)[:, 1])
    ours = metrics(y, [int(p >= 0.5) for p in ours_p])
    ours80 = metrics(y, [int(p >= 0.8) for p in ours_p])

    rules_det = {k: v for k, v in get_registered_detectors().items() if k not in ("ml_classifier", "semantic")}
    rules = metrics(y, [int(any(len(c().detect(t)) > 0 for c in rules_det.values())) for t in texts])

    # Confidence-distribution comparison -- the property Findings 8/9 turn on.
    pg_distinct = len(set(round(s, 4) for s in pg_scores))
    pg_ambiguous = sum(1 for s in pg_scores if 0.5 <= s < 0.8)
    ours_distinct = len(set(round(p, 4) for p in ours_p))
    ours_ambiguous = sum(1 for p in ours_p if 0.5 <= p < 0.8)

    result = {
        "n": len(texts), "threshold": args.threshold, "model": MODEL_ID,
        "prompt_guard_2_86m": pg, "sentinelcore_learned@0.5": ours,
        "sentinelcore_learned@0.8": ours80, "sentinelcore_rules": rules,
        "confidence_distribution": {
            "prompt_guard": {"distinct_values": pg_distinct, "in_ambiguous_band": pg_ambiguous},
            "learned": {"distinct_values": ours_distinct, "in_ambiguous_band": ours_ambiguous},
        },
    }
    OUT.write_text(json.dumps(result, indent=2))

    print(f"\n=== HEAD TO HEAD, held-out split n={len(texts)} ===\n")
    print(f"{'system':<32}{'prec':>9}{'recall':>9}{'F1':>9}{'FPR':>9}")
    for name, m in [("Meta Prompt Guard 2 (86M)", pg),
                    ("SentinelCore rules", rules),
                    ("SentinelCore learned @0.5", ours),
                    ("SentinelCore learned @0.8", ours80)]:
        print(f"{name:<32}{m['precision']:>8.1%}{m['recall']:>9.1%}{m['f1']:>9.1%}{m['fpr']:>9.1%}")

    print(f"\n=== CONFIDENCE DISTRIBUTION (Findings 8/9) ===")
    print(f"{'':<32}{'distinct':>10}{'in 0.5-0.8':>12}")
    print(f"{'Meta Prompt Guard 2':<32}{pg_distinct:>10}{pg_ambiguous:>12}")
    print(f"{'SentinelCore learned':<32}{ours_distinct:>10}{ours_ambiguous:>12}")
    print("\n(gpt-4o-mini verbalized: 8 distinct, 1 in band. logprobs: 8 distinct, 1 in band.)")
    print("\nIf Prompt Guard is well distributed here, Findings 8/9 are specific to")
    print("LLM-as-detector and do NOT generalise to trained classifiers -- which is")
    print("what we already believe, and this is the direct test of it.")
    print(f"\nwritten to {OUT}")


if __name__ == "__main__":
    main()
