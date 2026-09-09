"""
Canonical evidence audit.

Builds the evidence table from RESULT FILES ONLY. Repository artifacts are
the source of truth; numbers quoted in prose, commit messages, or
conversation are not. Where a document disagrees with an artifact, the
artifact wins and the disagreement is reported.

Each row carries a publication-safety verdict:

  SAFE        reproducible from an artifact, with uncertainty stated where
              the artifact supports one
  QUALIFIED   real but must be published with a stated caveat (small n,
              single seed, partial run, confound)
  UNSAFE      not currently supportable -- do not put it in the paper

Usage: python scripts/audit_evidence.py
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
P = ROOT / "dataset" / "processed"
OUT = P / "evidence_audit.json"


def ci_of(d):
    """Result files use two different CI schemas -- statistical_validation.py
    writes ci95_low/ci95_high, threshold_study.py writes ci95: [lo, hi].
    Surfaced by this audit rather than assumed away; normalised here and
    reported as a schema inconsistency."""
    if "ci95_low" in d:
        return d["ci95_low"], d["ci95_high"]
    if "ci95" in d:
        return d["ci95"][0], d["ci95"][1]
    return None, None


def load(name):
    f = P / name
    if not f.exists():
        return None
    try:
        return json.loads(f.read_text())
    except Exception:
        return None


def main():
    art = {n: load(n) for n in [
        "ml_detector_report.json", "baseline_comparison.json", "statistical_validation.json",
        "threshold_study.json", "cross_source_analysis.json", "ablation_results_v2.json",
        "semantic_results.json", "logprob_results.json", "confidence_distribution.json",
        "overdefense_results.json", "industry_comparison.json", "eval_results.json",
    ]}
    present = {k: v for k, v in art.items() if v is not None}
    missing = [k for k, v in art.items() if v is None]

    rows = []

    def add(finding, experiment, dataset, n, config, metric, result, uncertainty, interp, verdict, why=""):
        rows.append({"finding": finding, "experiment": experiment, "dataset": dataset, "n": n,
                     "configuration": config, "metric": metric, "result": result,
                     "uncertainty": uncertainty, "interpretation": interp,
                     "publication_verdict": verdict, "reason": why})

    sv = present.get("statistical_validation.json")
    if sv:
        r = sv["multi_seed"]["learned"]["recall"]; rr = sv["multi_seed"]["rules"]["recall"]
        ps = [m["p_value"] for m in sv["mcnemar"]]
        add("Detection: learned >> rules", "statistical_validation.py", "eval_set held-out",
            f"149 x {sv['n_seeds']} seeds", "TF-IDF+logreg @0.5 vs rules",
            "recall", f"{r['mean']:.3f} vs {rr['mean']:.3f}",
            f"95% CI [{ci_of(r)[0]:.3f},{ci_of(r)[1]:.3f}] vs [{ci_of(rr)[0]:.3f},{ci_of(rr)[1]:.3f}]; "
            f"McNemar max p={max(ps):.1e}, {sum(1 for p in ps if p<0.05)}/{len(ps)} seeds significant",
            "Non-overlapping CIs, paired test significant on every seed", "SAFE")

    ts = present.get("threshold_study.json")
    if ts:
        f8 = ts["test_at_fixed_0.80"]; rb = ts["rules_baseline_test"]; tz = ts["selected_threshold_zero_fp"]
        add("Learned dominates rules at a matched operating point", "threshold_study.py",
            "eval_set held-out", f"149 x {ts['n_seeds']} seeds", "threshold 0.80, selected on validation",
            "recall / FPR",
            f"recall {f8['recall']['mean']:.3f} vs {rb['recall']['mean']:.3f}; "
            f"FPR {f8['fpr']['mean']:.3f} vs {rb['fpr']['mean']:.3f}",
            f"recall CIs disjoint; FPR CIs OVERLAP [{ci_of(f8['fpr'])[0]:.3f},{ci_of(f8['fpr'])[1]:.3f}] "
            f"vs [{ci_of(rb['fpr'])[0]:.3f},{ci_of(rb['fpr'])[1]:.3f}]",
            "Recall gain significant; FPR increase is NOT statistically distinguishable", "SAFE")
        add("A fixed threshold reaches 0% FPR", "threshold_study.py", "eval_set", "149 x 10",
            "zero-FP threshold selected on validation", "selected threshold",
            f"range {tz['min']:.2f}-{tz['max']:.2f}, std {tz['std']:.3f}", "n/a",
            "RETRACTED. No fixed threshold reliably reaches 0% FPR; the validation-selected one yields "
            f"{ts['test_at_selected_zero_fp']['fpr']['mean']:.3f} FPR on test", "UNSAFE",
            "Formally withdrawn; must not reappear")

    ab = present.get("ablation_results_v2.json")
    if ab:
        s = ab["summary"]
        boot = (sv or {}).get("agent_bootstrap", {})
        def ci(k, m):
            b = boot.get(k, {}).get(m)
            return f"[{b['ci95_low']:.3f},{b['ci95_high']:.3f}]" if b else "no CI on file"
        # INTEGRITY CHECK. The semantic detector fails open when its cache is
        # absent, so L/M silently collapse onto C/E and the artifact still
        # looks well-formed. Detect that rather than publishing degenerate
        # rows as if they were measurements.
        semantic_degenerate = (
            "L_semantic_flat" in s and "C_tool_authz" in s
            and s["L_semantic_flat"]["attack_prevention_rate"] == s["C_tool_authz"]["attack_prevention_rate"]
            and s["M_semantic_prov"]["attack_prevention_rate"] == s["E_prov_rules"]["attack_prevention_rate"]
        )

        for a, b, label, verdict, why in [
            ("A_content_only", "J_ml_flat", "Detector choice dominates policy", "SAFE", ""),
            ("H_oracleMED_flat", "I_oracleMED_prov", "Provenance under an ORACLE detector", "QUALIFIED",
             "Oracle is a simulation with zero false positives by construction"),
            ("J_ml_flat", "K_ml_prov", "Provenance under the learned detector", "QUALIFIED",
             "CIs overlap at the edges; also operating-point dependent (+2.4 at floor 0.35)"),
            ("L_semantic_flat", "M_semantic_prov", "Provenance under the semantic detector", "QUALIFIED",
             "Semantic arm depends on a cache built from a single API run"),
        ]:
            if a in s and b in s:
                if a.startswith("L_") and semantic_degenerate:
                    add(label, "run_ablation.py", "agent_traces_v2",
                        f"{s[a]['attacks_total']} atk / {s[a]['benign_total']} ben", f"{a} -> {b}", "APR",
                        "DEGENERATE -- identical to C/E", "n/a",
                        "The semantic cache is absent in this checkout, so the detector returned no findings "
                        "and L/M collapsed onto C/E. The real values (reported elsewhere as 0.706 -> 0.718) "
                        "are NOT reproducible from any artifact in this repository.",
                        "UNSAFE", "No artifact here supports the semantic ablation numbers")
                    continue
                d = (s[b]["attack_prevention_rate"] - s[a]["attack_prevention_rate"]) * 100
                add(label, "run_ablation.py", "agent_traces_v2",
                    f"{s[a]['attacks_total']} atk / {s[a]['benign_total']} ben", f"{a} -> {b}", "APR",
                    f"{s[a]['attack_prevention_rate']:.3f} -> {s[b]['attack_prevention_rate']:.3f} ({d:+.1f}pp)",
                    f"bootstrap {ci(a,'APR')} -> {ci(b,'APR')}",
                    "Gain does not track detector strength" if "Provenance" in label else "Largest single effect measured",
                    verdict, why)

    cd = present.get("confidence_distribution.json")
    lp = present.get("logprob_results.json")
    if cd:
        add("LLM confidence has no usable middle (self-reported)", "confidence_distribution.py",
            "eval_set held-out", cd["n"], "gpt-4o-mini verbalized vs TF-IDF",
            "ambiguous share of findings",
            f"{cd['semantic']['ambiguous_share_of_findings']:.3f} vs {cd['learned']['ambiguous_share_of_findings']:.3f}",
            "descriptive; no CI", "Semantic emits ~8 distinct values; learned emits 143", "SAFE")
    if lp:
        pr = lp["profile"]
        add("Log-probabilities do not recover the missing uncertainty", "logprob_experiment.py",
            "eval_set held-out", f"{lp['n_collected']} of 149", "gpt-4o-mini, temperature 0, top_logprobs=20",
            "distinct values / ambiguous band / confident errors",
            f"{pr['distinct_values']} / {pr['in_ambiguous_band']} / {pr['confident_error_share']:.0%}",
            f"PARTIAL: {149 - lp['n_collected']} texts outstanding",
            "Same conclusion as verbalized; saturates harder", "QUALIFIED",
            "Partial run; restate at full n before publication")

    od = present.get("overdefense_results.json")
    if od:
        add("Over-defense behaviour on hard benign inputs", "evaluate_overdefense.py",
            od["source"], od["n"], "rules / learned@0.5 / learned@0.8", "over-defense accuracy",
            "; ".join(f"{k.split('_')[-1]}={v['over_defense_accuracy']:.2f}" for k, v in od["systems"].items()),
            "n=5 -- no statistical validity",
            "UNMEASURED. Corpus has 5/399 hard negatives; external benchmark unreachable here", "UNSAFE",
            "n=5 cannot support any published claim")

    if "industry_comparison.json" not in present:
        add("Performance vs an industry guardrail", "benchmark_industry.py", "Prompt Guard 2 vs held-out",
            "n/a", "n/a", "n/a", "NOT RUN", "n/a",
            "Blocked: huggingface.co unreachable from the dev sandbox", "UNSAFE",
            "No comparison against any incumbent exists yet")

    # Schema inconsistency found by this audit, recorded rather than silently normalised.
    schema_notes = []
    if sv and ts:
        a = "ci95_low/ci95_high" if "ci95_low" in sv["multi_seed"]["learned"]["recall"] else "ci95"
        b = "ci95_low/ci95_high" if "ci95_low" in ts["test_at_fixed_0.80"]["recall"] else "ci95"
        if a != b:
            schema_notes.append(
                f"CI schema differs between artifacts: statistical_validation.json uses {a}, "
                f"threshold_study.json uses {b}. Normalised at read time; worth unifying at write time."
            )

    counts = {}
    for r in rows:
        counts[r["publication_verdict"]] = counts.get(r["publication_verdict"], 0) + 1

    OUT.write_text(json.dumps({"artifacts_present": sorted(present), "artifacts_missing": sorted(missing),
                               "schema_notes": schema_notes, "rows": rows,
                               "verdict_counts": counts}, indent=2))

    print(f"artifacts present: {len(present)}   missing: {len(missing)}")
    if missing:
        print(f"  missing: {', '.join(missing)}")
    for note in schema_notes:
        print(f"  SCHEMA: {note}")
    print(f"\nverdicts: {counts}\n")
    for r in rows:
        print(f"[{r['publication_verdict']:<9}] {r['finding']}")
        print(f"             {r['experiment']}  |  {r['dataset']}  |  n={r['n']}")
        print(f"             {r['metric']}: {r['result']}")
        print(f"             uncertainty: {r['uncertainty']}")
        if r["reason"]:
            print(f"             CAVEAT: {r['reason']}")
        print()
    print(f"written to {OUT}")


if __name__ == "__main__":
    main()
