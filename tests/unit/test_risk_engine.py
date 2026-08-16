"""Unit tests for the risk engine."""

from app.models.finding import Finding, Severity
from app.services.risk_engine import calculate_risk_score


def _finding(severity: Severity) -> Finding:
    return Finding(detector="test", type="test_type", description="test", severity=severity)


def test_no_findings_zero_score():
    assert calculate_risk_score([]) == 0


def test_single_low_finding():
    assert calculate_risk_score([_finding(Severity.LOW)]) == 10


def test_single_medium_finding():
    assert calculate_risk_score([_finding(Severity.MEDIUM)]) == 30


def test_single_high_finding():
    assert calculate_risk_score([_finding(Severity.HIGH)]) == 60


def test_single_critical_finding():
    assert calculate_risk_score([_finding(Severity.CRITICAL)]) == 90


def test_multiple_findings_add_diminishing_contribution():
    score = calculate_risk_score([_finding(Severity.HIGH), _finding(Severity.HIGH)])
    assert score == 69  # 60 base + (60 * 0.15) from the second finding


def test_score_is_capped_at_100():
    findings = [_finding(Severity.CRITICAL) for _ in range(5)]
    assert calculate_risk_score(findings) == 100


def test_score_always_in_valid_range():
    scenarios = [
        [],
        [_finding(Severity.LOW)],
        [_finding(Severity.CRITICAL)] * 3,
        [_finding(Severity.LOW), _finding(Severity.MEDIUM), _finding(Severity.HIGH)],
    ]
    for findings in scenarios:
        score = calculate_risk_score(findings)
        assert 0 <= score <= 100
