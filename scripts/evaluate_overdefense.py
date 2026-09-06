"""
Over-defense evaluation: how often does a detector block BENIGN text that
merely talks about attacks?

WHY THIS MATTERS MORE THAN IT SOUNDS
Every false-positive rate this project has reported is measured on a
benign set whose text does not resemble an attack. Of 399 benign examples
in our corpus, **5** contain attack-adjacent vocabulary -- 1.3%. So our
FPR numbers are, structurally, easy-negative FPRs. They say almost nothing
about the failure mode operators actually complain about: the security
tool that blocks a user asking "what is prompt injection?".

This is not a hypothetical weakness. The published NotInject benchmark
(InjecGuard, arXiv:2410.22770) reports over-defense accuracy as low as
0.88% for PromptGuard and 5.31% for Deepset's classifier -- i.e. those
models flag almost all benign text containing trigger words. A detector
can look excellent on a standard benchmark and be unusable in production
for exactly this reason.

TWO WAYS TO RUN IT

  1. Against the real NotInject benchmark (preferred):
         python scripts/evaluate_overdefense.py --dataset notinject
     Requires `pip install datasets`. Downloads from HuggingFace.

  2. Against any local JSONL of benign-but-trigger-laden text:
         python scripts/evaluate_overdefense.py --file path/to/benign.jsonl
     Schema: one object per line with a "text" field. Every row is assumed
     BENIGN -- this measures over-defense only, so a positive is by
     definition a false positive.

  3. Against the 5 examples our own corpus contains, as a smoke test:
         python scripts/evaluate_overdefense.py --dataset internal
     n=5. Reported for completeness and explicitly too small to conclude
     from; it exists to prove the pipeline runs, not to produce a number.

WHAT COUNTS AS SUCCESS
A high over-defense accuracy: the fraction of benign-with-trigger-words
text correctly NOT flagged. This is the axis where the strongest
detectors in the literature do worst, and where a system that is honest
about the security/utility frontier can legitimately compete.
"""

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

ROOT = Path(__file__).parent.parent
EVAL = ROOT / "dataset" / "processed" / "eval_set.jsonl"
OUT = ROOT / "dataset" / "processed" / "overdefense_results.json"

TRIGGERS = re.compile(
    r"\b(ignore|instruction|system|prompt|override|bypass|jailbreak|pretend|role|"
    r"rule|restriction|disregard|forget|reveal|admin|password)", re.I
)


def load_internal():
    recs = [json.loads(l) for l in EVAL.read_text(encoding="utf-8").splitlines() if l.strip()]
    return [r["text"] for r in recs if r["label"] == "benign" and TRIGGERS.search(r["text"])]


def load_notinject():
    try:
        from datasets import load_dataset
    except ImportError:
        print("pip install datasets"); sys.exit(1)
    # NotInject ships as benign prompts containing trigger words, grouped
    # by how many triggers each contains.
    for name in ("leolee99/NotInject", "SaFoLab-WISC/NotInject"):
        try:
            ds = load_dataset(name)
            split = next(iter(ds.values()))
            col = "prompt" if "prompt" in split.column_names else split.column_names[0]
            return [r[col] for r in split]
        except Exception:
            continue
    print("Could not load NotInject automatically. Download it manually and use --file.")
    sys.exit(1)


def load_file(path):
    rows = [json.loads(l) for l in Path(path).read_text(encoding="utf-8").splitlines() if l.strip()]
    return [r["text"] for r in rows]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", choices=["internal", "notinject"], default="internal")
    ap.add_argument("--file")
    args = ap.parse_args()

    if args.file:
        texts, source = load_file(args.file), Path(args.file).name
    elif args.dataset == "notinject":
        texts, source = load_notinject(), "NotInject"
    else:
        texts, source = load_internal(), "internal (benign + trigger words)"

    if not texts:
        print("No texts loaded."); sys.exit(1)

    from app.detectors.registry import get_registered_detectors
    import joblib

    rules = {k: v for k, v in get_registered_detectors().items() if k not in ("ml_classifier", "semantic")}
    model = joblib.load(ROOT / "dataset" / "processed" / "ml_detector.joblib")
    probs = list(model.predict_proba(texts)[:, 1])

    # bool() casts are load-bearing: numpy comparisons yield numpy bools,
    # which sum to int64 and are not JSON-serialisable.
    systems = {
        "sentinelcore_rules": [bool(any(len(c().detect(t)) > 0 for c in rules.values())) for t in texts],
        "sentinelcore_learned@0.5": [bool(p >= 0.5) for p in probs],
        "sentinelcore_learned@0.8": [bool(p >= 0.8) for p in probs],
    }

    result = {"source": source, "n": len(texts), "systems": {}}
    print(f"Over-defense evaluation -- {source}, n={len(texts)}")
    if len(texts) < 30:
        print(f"\n  WARNING: n={len(texts)} is too small to conclude from. Reported to show")
        print("  the pipeline runs. Use --dataset notinject for a real measurement.\n")

    print(f"{'system':<30}{'flagged':>10}{'over-defense acc':>20}")
    for name, flags in systems.items():
        flagged = int(sum(flags))
        acc = 1 - flagged / len(texts)
        result["systems"][name] = {"flagged": flagged, "over_defense_accuracy": round(acc, 4)}
        print(f"{name:<30}{flagged:>10}{acc:>19.1%}")

    print("\npublished comparison (InjecGuard, arXiv:2410.22770, on NotInject):")
    print(f"  {'PromptGuard':<28}{'':>10}{0.0088:>19.1%}")
    print(f"  {'Deepset':<28}{'':>10}{0.0531:>19.1%}")
    print(f"  {'ProtectAI v2':<28}{'':>10}{0.5664:>19.1%}")
    print(f"  {'InjecGuard':<28}{'':>10}{0.8732:>19.1%}")
    print("\n  (those numbers are on NotInject itself; ours are comparable only")
    print("   when run with --dataset notinject)")

    OUT.write_text(json.dumps(result, indent=2))
    print(f"\nwritten to {OUT}")


if __name__ == "__main__":
    main()
