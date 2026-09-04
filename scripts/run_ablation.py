"""
Agent-trace ablation study.

Replays deterministic agent traces through the SentinelCore pipeline under
different component configurations, and measures ACTION-LEVEL outcomes
rather than text-classification outcomes:

    Attack Prevention Rate (APR)  -- attack scenarios where the unsafe
                                     action / injected instruction was
                                     blocked or escalated
    Benign Completion Rate (BCR)  -- benign scenarios allowed to complete
                                     (utility; the cost side of security)

Ablation configurations, isolating each mechanism:

    A  content-only    detectors + risk + policy, origin ignored,
                       no tool-name authorization        (the 2025 baseline)
    B  + prov scoring  origin trust SCORE scaling enabled
    C  + tool authz    deterministic tool-name authorization enabled
    D  scoring+authz   both of the above
    E  + prov RULES    origin-conditioned POLICY RULES enabled

    E exists because B produced a null result: score weighting is
    subsumed by categorical per-type rules that never consult the
    threshold. E tests whether applying provenance at the RULE layer
    instead changes that -- the hypothesis the ablation itself generated.

The point is CAUSAL: if B and C both matter, APR should rise for different
scenario categories, and the categories should be predictable from the
mechanism. If a component changes nothing, that is reported as a null
result, not quietly dropped.

Usage: python scripts/run_ablation.py
"""

import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.detectors.ml_classifier.detector import HIGH_CONFIDENCE, REPORTING_FLOOR  # noqa: E402
from app.detectors.registry import get_registered_detectors  # noqa: E402
from app.models.finding import Decision, Finding, Severity  # noqa: E402
from app.services.policy_engine import decide, load_policy, most_severe  # noqa: E402
from app.services.risk_engine import calculate_risk_score  # noqa: E402
from app.services.tool_policy import authorize_tool  # noqa: E402

import os

_V2 = os.environ.get("SENTINELCORE_TRACES_V2", "1") == "1"
TRACES = Path(__file__).parent.parent / "dataset" / "processed" / (
    "agent_traces_v2.jsonl" if _V2 else "agent_traces.jsonl"
)
RESULTS = Path(__file__).parent.parent / "dataset" / "processed" / ("ablation_results_v2.json" if _V2 else "ablation_results.json")

# A scenario counts as DEFENDED if the pipeline reaches any of these.
# WARN is deliberately excluded: a warning does not stop anything, and
# counting it as prevention is exactly the "decision reported as
# enforcement" error this project treats as a correctness bug.
BLOCKING = {Decision.BLOCK, Decision.SANITIZE, Decision.HUMAN_APPROVAL}

CONFIGS = {
    "A_content_only": {"provenance": False, "tool_authz": False, "origin_rules": False},
    "B_prov_scoring": {"provenance": True, "tool_authz": False, "origin_rules": False},
    "C_tool_authz": {"provenance": False, "tool_authz": True, "origin_rules": False},
    "D_scoring_authz": {"provenance": True, "tool_authz": True, "origin_rules": False},
    "E_prov_rules": {"provenance": True, "tool_authz": True, "origin_rules": True},
    # Oracle-detector conditions: isolate the POLICY layer by removing
    # detection recall as the bottleneck. Tests Finding 3 causally.
    # Oracle-detector conditions: remove detection recall as the
    # bottleneck to test Finding 3 causally.
    # HIGH severity saturates the score threshold (ceiling effect).
    "F_oracleHI_flat": {"provenance": False, "tool_authz": True, "origin_rules": False, "oracle": Severity.HIGH},
    "G_oracleHI_prov": {"provenance": True, "tool_authz": True, "origin_rules": True, "oracle": Severity.HIGH},
    # MEDIUM severity = ambiguous signal, leaves headroom for provenance.
    "H_oracleMED_flat": {"provenance": False, "tool_authz": True, "origin_rules": False, "oracle": Severity.MEDIUM},
    "I_oracleMED_prov": {"provenance": True, "tool_authz": True, "origin_rules": True, "oracle": Severity.MEDIUM},
    # REAL learned detector replacing the oracle -- tests Finding 4
    # outside simulation.
    "J_ml_flat": {"provenance": False, "tool_authz": True, "origin_rules": False, "ml": True},
    "K_ml_prov": {"provenance": True, "tool_authz": True, "origin_rules": True, "ml": True},
}


# Experimental origin rules for the learned detector. NOT shipped in the
# default policy: Finding 5 measured them as net-negative (0pp APR, -20pp
# BCR). Kept here so config K remains exactly reproducible.
EXPERIMENTAL_ML_ORIGIN_RULES = {
    "ml_injection@context": "block",
    "ml_injection@tool_response": "block",
    "ml_injection@tool_description": "block",
    "ml_injection@tool_arguments": "block",
    "ml_injection@input": "warn",
}


def _policy_with_experimental_rules():
    p = load_policy()
    p = {**p, "origin_rules": {**p.get("origin_rules", {}), **EXPERIMENTAL_ML_ORIGIN_RULES}}
    return p


_EXPERIMENTAL_POLICY = None
_ML_MODEL = None


def _ml_findings(text: str, origin: str) -> list[Finding]:
    """
    Real learned detector (TF-IDF -> calibrated logistic regression),
    replacing the ground-truth oracle. Probability is mapped to severity
    so the detector expresses UNCERTAINTY rather than a binary hit --
    the property Finding 4 identifies as the precondition for provenance
    to matter.

    Bands are imported from the shipped detector rather than duplicated,
    so the experiment always reflects deployed behaviour. They were derived
    by scripts/threshold_study.py (10 seeds, selection on validation only).
    """
    global _ML_MODEL
    if _ML_MODEL is None:
        import joblib

        _ML_MODEL = joblib.load(Path(__file__).parent.parent / "dataset" / "processed" / "ml_detector.joblib")

    p = float(_ML_MODEL.predict_proba([text])[0][1])
    if p < REPORTING_FLOOR:
        return []
    sev = Severity.HIGH if p >= HIGH_CONFIDENCE else Severity.MEDIUM
    f = Finding(
        detector="ml_classifier",
        type="ml_injection",
        description=f"learned classifier flagged content (p={p:.2f})",
        severity=sev,
        confidence=round(p, 4),
    )
    f.origin = origin
    return [f]


def _oracle_findings(ev: dict, origin: str, severity: Severity) -> list[Finding]:
    """
    Oracle detector: perfect recall on attacker-authored CONTENT, by
    ground-truth label. Not a real detector -- an experimental upper bound
    used to answer a single question: does provenance change outcomes when
    detection is no longer the bottleneck?

    Run at two severities on purpose. A HIGH-severity oracle scores 60,
    which already clears the `sanitize` threshold of 50, so the outcome is
    decided before provenance is ever consulted -- a ceiling effect that
    makes the provenance comparison meaningless. A MEDIUM-severity oracle
    scores 30 (WARN, not prevention), leaving the headroom needed to ask
    whether provenance can safely escalate untrusted origins. Both are
    reported; the difference between them is itself a result.
    """
    if not ev.get("oracle_malicious"):
        return []
    f = Finding(
        detector="oracle",
        type="oracle_injection",
        description="ground-truth attacker-authored content",
        severity=severity,
    )
    f.origin = origin
    return [f]


def _scan(text: str, origin: str) -> list[Finding]:
    findings: list[Finding] = []
    for cls in get_registered_detectors().values():
        detected = cls().detect(text)
        for f in detected:
            f.origin = origin
        findings.extend(detected)
    return findings


def evaluate_trace(events: list[dict], provenance: bool, tool_authz: bool, origin_rules: bool = False, oracle: Severity | None = None, ml: bool = False) -> Decision:
    """Replays one trace, returning the most severe decision reached."""
    decisions: list[Decision] = []
    doc_index = 0

    for ev in events:
        kind = ev["kind"]
        findings: list[Finding] = []
        local: list[Decision] = []

        if kind == "user_input":
            origin = "input"
            findings = _scan(ev["text"], origin)
        elif kind == "retrieved_doc":
            origin = f"context:{doc_index}"
            findings = _scan(ev["text"], origin)
            doc_index += 1
        elif kind == "tool_response":
            origin = "tool_response"
            findings = _scan(ev["text"], origin)
        elif kind == "mcp_tool_def":
            origin = f"tool_description:{ev['name']}"
            findings = _scan(ev["text"], origin)
        elif kind == "tool_call":
            name = ev["name"]
            origin = f"tool_arguments:{name}"
            if tool_authz:
                local.append(authorize_tool(name))
            findings = _scan(json.dumps(ev["arguments"]), origin)
        else:
            origin = "input"

        if oracle:
            findings = findings + _oracle_findings(ev, origin, oracle)
        if ml:
            text_for_ml = ev.get("text") or json.dumps(ev.get("arguments", {}))
            findings = findings + _ml_findings(text_for_ml, origin)

        score = calculate_risk_score(findings, use_origin_trust=provenance)
        global _EXPERIMENTAL_POLICY
        if ml and origin_rules:
            if _EXPERIMENTAL_POLICY is None:
                _EXPERIMENTAL_POLICY = _policy_with_experimental_rules()
            local.append(decide(findings, score, policy=_EXPERIMENTAL_POLICY, use_origin_rules=True))
        else:
            local.append(decide(findings, score, use_origin_rules=origin_rules))
        decisions.extend(local)

    return most_severe(decisions) if decisions else Decision.ALLOW


def main():
    if not TRACES.exists():
        print(f"Missing {TRACES}. Run scripts/build_agent_traces_v2.py (or set SENTINELCORE_TRACES_V2=0)")
        sys.exit(1)

    scenarios = [json.loads(line) for line in TRACES.read_text(encoding="utf-8").splitlines() if line.strip()]
    attacks = [s for s in scenarios if s["label"] == "attack"]
    benign = [s for s in scenarios if s["label"] == "benign"]

    results = {}
    per_scenario = defaultdict(dict)

    for cfg_name, cfg in CONFIGS.items():
        prevented, completed = 0, 0
        by_category = defaultdict(lambda: {"total": 0, "prevented": 0})

        for s in attacks:
            d = evaluate_trace(s["events"], cfg["provenance"], cfg["tool_authz"], cfg["origin_rules"], cfg.get("oracle"), cfg.get("ml", False))
            ok = d in BLOCKING
            prevented += ok
            by_category[s["category"]]["total"] += 1
            by_category[s["category"]]["prevented"] += ok
            per_scenario[s["id"]][cfg_name] = d.value

        for s in benign:
            d = evaluate_trace(s["events"], cfg["provenance"], cfg["tool_authz"], cfg["origin_rules"], cfg.get("oracle"), cfg.get("ml", False))
            ok = d not in BLOCKING
            completed += ok
            per_scenario[s["id"]][cfg_name] = d.value

        results[cfg_name] = {
            "config": {k: (v.value if hasattr(v, "value") else v) for k, v in cfg.items()},
            "attack_prevention_rate": round(prevented / len(attacks), 4),
            "benign_completion_rate": round(completed / len(benign), 4),
            "attacks_prevented": prevented,
            "attacks_total": len(attacks),
            "benign_completed": completed,
            "benign_total": len(benign),
            "by_category": {k: {**v, "apr": round(v["prevented"] / v["total"], 4)} for k, v in sorted(by_category.items())},
        }

    RESULTS.write_text(
        json.dumps({"summary": results, "per_scenario": dict(per_scenario)}, indent=2), encoding="utf-8"
    )

    print(f"Agent-trace ablation -- {len(attacks)} attack / {len(benign)} benign scenarios\n")
    print(f"{'Config':<18}{'APR':>8}{'BCR':>8}   (prevented / completed)")
    print("-" * 58)
    for name, r in results.items():
        print(
            f"{name:<18}{r['attack_prevention_rate']:>7.1%}{r['benign_completion_rate']:>8.1%}"
            f"   {r['attacks_prevented']}/{r['attacks_total']}  {r['benign_completed']}/{r['benign_total']}"
        )

    print("\nAttack prevention by category:")
    cats = sorted({c for r in results.values() for c in r["by_category"]})
    print(f"{'category':<22}" + "".join(f"{n.split('_')[0]:>8}" for n in CONFIGS))
    for cat in cats:
        row = f"{cat:<22}"
        for name in CONFIGS:
            bc = results[name]["by_category"].get(cat)
            row += f"{bc['apr']:>7.0%} " if bc else f"{'-':>8}"
        print(row)

    print(f"\nFull results: {RESULTS}")


if __name__ == "__main__":
    main()
