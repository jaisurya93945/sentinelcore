"""
Risk Engine.

Combines findings into a single 0-100 risk score. Deterministic and
transparent by design -- no ML or statistical model until one is built AND
benchmarked against this baseline (project Authenticity Policy).

Formula: the highest-severity finding sets the base score, and each
additional finding adds a diminishing 15% of its own weight on top --
more signals firing raises risk, but five LOW findings shouldn't equal one
CRITICAL finding. Capped at 100.

Severity weights are additionally scaled by PROVENANCE: the same finding
is more dangerous arriving from a retrieved document or a model-generated
tool argument than from the user's own message. See
app/services/origin_trust.py for the trust model and an explicit statement
of what is a modeling choice vs. an empirical result.

`use_origin_trust=False` disables that scaling entirely, reproducing the
pre-provenance behaviour exactly. This is not a legacy flag -- it's the
control condition for the ablation study (does provenance-awareness
actually improve anything?), and removing it would make that experiment
impossible to run.

Confidence is intentionally NOT factored in: every v0.1 detector is a
deterministic rule match, not calibrated ML, so each finding is treated as
certain by definition. Confidence-weighted scoring only becomes meaningful
once a calibrated detector actually exists -- see docs/threat-model/README.md.
"""

from app.models.finding import Finding, Severity
from app.services.origin_trust import trust_multiplier

SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.LOW: 10,
    Severity.MEDIUM: 30,
    Severity.HIGH: 60,
    Severity.CRITICAL: 90,
}

ADDITIONAL_FINDING_FACTOR = 0.15


def calculate_risk_score(findings: list[Finding], use_origin_trust: bool = True) -> int:
    if not findings:
        return 0

    weights = []
    for f in findings:
        base = SEVERITY_WEIGHTS[f.severity]
        if use_origin_trust:
            base *= trust_multiplier(f.origin)
        weights.append(base)

    scores = sorted(weights, reverse=True)
    base = scores[0]
    additional = sum(score * ADDITIONAL_FINDING_FACTOR for score in scores[1:])

    return min(100, round(base + additional))
