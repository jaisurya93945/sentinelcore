"""
Tests for provenance-aware risk scoring.

The central property under test: the SAME finding produces a HIGHER risk
score when it arrives from less-trusted provenance. Before this existed,
origin was tracked and then ignored, making "provenance-aware" a false
claim -- these tests exist to keep it true.
"""

from app.models.finding import Decision, Finding, Severity
from app.services.origin_trust import DEFAULT_MULTIPLIER, trust_multiplier
from app.services.policy_engine import decide
from app.services.risk_engine import calculate_risk_score


def _finding(origin: str, severity: Severity = Severity.MEDIUM) -> Finding:
    f = Finding(detector="test", type="system_prompt_extraction", description="test", severity=severity)
    f.origin = origin
    return f


def test_trust_multiplier_resolves_bare_origins():
    assert trust_multiplier("input") == 1.0
    assert trust_multiplier("context") == 1.5
    assert trust_multiplier("tool_arguments") == 1.8


def test_trust_multiplier_resolves_suffixed_origins():
    """Origins carry suffixes like context:2 and tool_arguments:shell.execute."""
    assert trust_multiplier("context:0") == trust_multiplier("context")
    assert trust_multiplier("context:17") == trust_multiplier("context")
    assert trust_multiplier("tool_arguments:shell.execute") == trust_multiplier("tool_arguments")
    assert trust_multiplier("tool_description:web_search") == trust_multiplier("tool_description")


def test_unknown_origin_falls_back_to_neutral():
    """An unrecognized origin must never silently inflate or deflate a score."""
    assert trust_multiplier("some_future_origin") == DEFAULT_MULTIPLIER
    assert trust_multiplier("") == DEFAULT_MULTIPLIER


def test_same_finding_scores_higher_from_untrusted_provenance():
    user = calculate_risk_score([_finding("input")])
    rag = calculate_risk_score([_finding("context:0")])
    tool_arg = calculate_risk_score([_finding("tool_arguments:shell.execute")])

    assert user < rag < tool_arg, "provenance must produce a strict trust ordering"


def test_provenance_can_change_the_actual_decision():
    """Scoring differently is only meaningful if it changes what happens."""
    user_findings = [_finding("input")]
    tool_findings = [_finding("tool_arguments:shell.execute")]

    user_decision = decide(user_findings, calculate_risk_score(user_findings))
    tool_decision = decide(tool_findings, calculate_risk_score(tool_findings))

    assert user_decision == Decision.WARN
    assert tool_decision == Decision.SANITIZE


def test_origin_trust_can_be_disabled_for_ablation():
    """The control condition for the ablation study: with trust scaling off,
    provenance must have exactly zero effect."""
    origins = ["input", "output", "context:0", "tool_arguments:x", "tool_description:y"]
    scores = [calculate_risk_score([_finding(o)], use_origin_trust=False) for o in origins]
    assert len(set(scores)) == 1, "origin must not affect score when trust scaling is disabled"


def test_disabled_trust_reproduces_original_severity_weights():
    assert calculate_risk_score([_finding("input", Severity.LOW)], use_origin_trust=False) == 10
    assert calculate_risk_score([_finding("input", Severity.MEDIUM)], use_origin_trust=False) == 30
    assert calculate_risk_score([_finding("input", Severity.HIGH)], use_origin_trust=False) == 60
    assert calculate_risk_score([_finding("input", Severity.CRITICAL)], use_origin_trust=False) == 90


def test_score_still_capped_at_100_with_trust_scaling():
    findings = [_finding("tool_arguments:x", Severity.CRITICAL) for _ in range(5)]
    assert calculate_risk_score(findings) == 100


def test_no_findings_is_zero_regardless_of_trust_setting():
    assert calculate_risk_score([]) == 0
    assert calculate_risk_score([], use_origin_trust=False) == 0
