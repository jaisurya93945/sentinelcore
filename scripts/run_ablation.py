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
    B  + provenance    origin trust scaling enabled
    C  + tool authz    deterministic tool-name authorization enabled
    D  full            both

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

from app.detectors.registry import get_registered_detectors  # noqa: E402
from app.models.finding import Decision, Finding  # noqa: E402
from app.services.policy_engine import decide, most_severe  # noqa: E402
from app.services.risk_engine import calculate_risk_score  # noqa: E402
from app.services.tool_policy import authorize_tool  # noqa: E402

TRACES = Path(__file__).parent.parent / "dataset" / "processed" / "agent_traces.jsonl"
RESULTS = Path(__file__).parent.parent / "dataset" / "processed" / "ablation_results.json"

# A scenario counts as DEFENDED if the pipeline reaches any of these.
# WARN is deliberately excluded: a warning does not stop anything, and
# counting it as prevention is exactly the "decision reported as
# enforcement" error this project treats as a correctness bug.
BLOCKING = {Decision.BLOCK, Decision.SANITIZE, Decision.HUMAN_APPROVAL}

CONFIGS = {
    "A_content_only": {"provenance": False, "tool_authz": False},
    "B_provenance": {"provenance": True, "tool_authz": False},
    "C_tool_authz": {"provenance": False, "tool_authz": True},
    "D_full": {"provenance": True, "tool_authz": True},
}


def _scan(text: str, origin: str) -> list[Finding]:
    findings: list[Finding] = []
    for cls in get_registered_detectors().values():
        detected = cls().detect(text)
        for f in detected:
            f.origin = origin
        findings.extend(detected)
    return findings


def evaluate_trace(events: list[dict], provenance: bool, tool_authz: bool) -> Decision:
    """Replays one trace, returning the most severe decision reached."""
    decisions: list[Decision] = []
    doc_index = 0

    for ev in events:
        kind = ev["kind"]
        findings: list[Finding] = []
        local: list[Decision] = []

        if kind == "user_input":
            findings = _scan(ev["text"], "input")
        elif kind == "retrieved_doc":
            findings = _scan(ev["text"], f"context:{doc_index}")
            doc_index += 1
        elif kind == "tool_response":
            findings = _scan(ev["text"], "tool_response")
        elif kind == "mcp_tool_def":
            findings = _scan(ev["text"], f"tool_description:{ev['name']}")
        elif kind == "tool_call":
            name = ev["name"]
            if tool_authz:
                local.append(authorize_tool(name))
            findings = _scan(json.dumps(ev["arguments"]), f"tool_arguments:{name}")

        score = calculate_risk_score(findings, use_origin_trust=provenance)
        local.append(decide(findings, score))
        decisions.extend(local)

    return most_severe(decisions) if decisions else Decision.ALLOW


def main():
    if not TRACES.exists():
        print("Run: python scripts/build_agent_traces.py")
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
            d = evaluate_trace(s["events"], cfg["provenance"], cfg["tool_authz"])
            ok = d in BLOCKING
            prevented += ok
            by_category[s["category"]]["total"] += 1
            by_category[s["category"]]["prevented"] += ok
            per_scenario[s["id"]][cfg_name] = d.value

        for s in benign:
            d = evaluate_trace(s["events"], cfg["provenance"], cfg["tool_authz"])
            ok = d not in BLOCKING
            completed += ok
            per_scenario[s["id"]][cfg_name] = d.value

        results[cfg_name] = {
            "config": cfg,
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
