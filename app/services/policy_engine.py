"""
Policy Engine.

Maps findings + risk score to a final Decision
(ALLOW/WARN/SANITIZE/HUMAN_APPROVAL/BLOCK). Two layers, most-severe-wins:

  1. Per-finding-type rules (policy.yaml) -- if any finding matches a rule,
     that rule's decision is a candidate.
  2. Risk-score thresholds -- fallback for finding types with no explicit
     rule, based on the aggregate score from the Risk Engine.

The final decision is the single most severe candidate across both layers.
Deterministic and fully configurable via policy.yaml -- no hidden logic.
See docs/threat-model/README.md for design notes and known limitations.

`most_severe` is exported (not private) because tool-call scanning
(app/api/v1/tool_call.py) needs to combine this engine's content-based
decision with a completely separate, deterministic tool-name authorization
lookup (app/services/tool_policy.py) using the exact same severity
ordering, rather than duplicating it.
"""

from pathlib import Path

import yaml

from app.models.finding import Decision, Finding

DEFAULT_POLICY_PATH = Path(__file__).parent / "policy.yaml"

_DECISION_SEVERITY = [Decision.BLOCK, Decision.HUMAN_APPROVAL, Decision.SANITIZE, Decision.WARN, Decision.ALLOW]


def load_policy(path: Path | None = None) -> dict:
    policy_path = path or DEFAULT_POLICY_PATH
    with open(policy_path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def most_severe(decisions: list[Decision]) -> Decision:
    for candidate in _DECISION_SEVERITY:
        if candidate in decisions:
            return candidate
    return Decision.ALLOW


def decide(
    findings: list[Finding],
    risk_score: int,
    policy: dict | None = None,
    use_origin_rules: bool = True,
) -> Decision:
    """
    Two-layer, most-severe-wins.

    `origin_rules` (optional, keyed `<finding_type>@<origin_prefix>`) is
    consulted BEFORE the flat per-type rule. This exists because of a
    measured negative result: origin-weighted *scoring* changed nothing in
    the agent-trace ablation, since categorical per-type rules fire
    regardless of score and never consult the threshold the weighting
    affects (see docs/research/README.md, Finding 2). Provenance only
    changes behaviour if it conditions the RULE, which is what this does.

    `use_origin_rules=False` is the ablation control, matching
    `use_origin_trust=False` in the risk engine.
    """
    policy = policy if policy is not None else load_policy()
    rules: dict[str, str] = policy.get("rules", {})
    origin_rules: dict[str, str] = policy.get("origin_rules", {}) if use_origin_rules else {}
    thresholds: dict[str, int] = policy.get("thresholds", {})

    candidates: list[Decision] = []

    for finding in findings:
        origin_prefix = finding.origin.split(":", 1)[0]
        keyed = f"{finding.type}@{origin_prefix}"
        if keyed in origin_rules:
            candidates.append(Decision(origin_rules[keyed]))
        elif finding.type in rules:
            candidates.append(Decision(rules[finding.type]))

    if risk_score >= thresholds.get("block", 100):
        candidates.append(Decision.BLOCK)
    elif risk_score >= thresholds.get("sanitize", 100):
        candidates.append(Decision.SANITIZE)
    elif risk_score >= thresholds.get("warn", 100):
        candidates.append(Decision.WARN)
    else:
        candidates.append(Decision.ALLOW)

    return most_severe(candidates)
