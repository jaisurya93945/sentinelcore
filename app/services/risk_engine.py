"""
Risk Engine.

Combines findings into a single 0-100 risk score. Deterministic and
transparent by design -- no ML or statistical model until one is built AND
benchmarked against this baseline (project Authenticity Policy).

Formula: the highest-severity finding sets the base score, and each
additional finding adds a diminishing 15% of its own weight on top --
more signals firing raises risk, but five LOW findings shouldn't equal one
CRITICAL finding. Capped at 100.

Confidence is intentionally NOT factored in: every v0.1 detector is a
deterministic rule match, not calibrated ML, so each finding is treated as
certain by definition. Confidence-weighted scoring only becomes meaningful
once a calibrated detector actually exists -- see docs/threat-model/README.md.
"""

from app.models.finding import Finding, Severity

SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.LOW: 10,
    Severity.MEDIUM: 30,
    Severity.HIGH: 60,
    Severity.CRITICAL: 90,
}

# Each additional finding beyond the highest-severity one contributes this
# fraction of its own weight to the total. Chosen, not benchmarked yet --
# see Known Limitations in docs/threat-model/README.md.
ADDITIONAL_FINDING_FACTOR = 0.15


def calculate_risk_score(findings: list[Finding]) -> int:
    if not findings:
        return 0

    scores = sorted((SEVERITY_WEIGHTS[f.severity] for f in findings), reverse=True)
    base = scores[0]
    additional = sum(score * ADDITIONAL_FINDING_FACTOR for score in scores[1:])

    return min(100, round(base + additional))
