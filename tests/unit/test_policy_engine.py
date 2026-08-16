"""Unit tests for the policy engine."""

from app.models.finding import Decision, Finding, Severity
from app.services.policy_engine import decide, load_policy

TEST_POLICY = {
    "rules": {
        "instruction_override": "block",
        "zero_width_characters": "sanitize",
        "system_prompt_extraction": "warn",
    },
    "thresholds": {"block": 70, "sanitize": 50, "warn": 25},
}


def _finding(type_: str, severity: Severity = Severity.MEDIUM) -> Finding:
    return Finding(detector="test", type=type_, description="test", severity=severity)


def test_no_findings_allows():
    assert decide([], risk_score=0, policy=TEST_POLICY) == Decision.ALLOW


def test_explicit_block_rule_wins_even_with_low_score():
    findings = [_finding("instruction_override", Severity.LOW)]
    # a single LOW finding alone would only score 10 -- well under any threshold
    assert decide(findings, risk_score=10, policy=TEST_POLICY) == Decision.BLOCK


def test_explicit_sanitize_rule_applies():
    findings = [_finding("zero_width_characters")]
    assert decide(findings, risk_score=10, policy=TEST_POLICY) == Decision.SANITIZE


def test_unmapped_finding_type_falls_back_to_threshold():
    findings = [_finding("some_future_finding_type")]
    assert decide(findings, risk_score=80, policy=TEST_POLICY) == Decision.BLOCK
    assert decide(findings, risk_score=55, policy=TEST_POLICY) == Decision.SANITIZE
    assert decide(findings, risk_score=30, policy=TEST_POLICY) == Decision.WARN
    assert decide(findings, risk_score=5, policy=TEST_POLICY) == Decision.ALLOW


def test_most_severe_decision_wins_across_multiple_findings():
    findings = [_finding("system_prompt_extraction"), _finding("instruction_override")]
    # one rule says warn, the other says block -- block should win
    assert decide(findings, risk_score=20, policy=TEST_POLICY) == Decision.BLOCK


def test_default_policy_file_loads_and_produces_valid_decision():
    policy = load_policy()
    assert "rules" in policy
    assert "thresholds" in policy
    findings = [_finding("instruction_override", Severity.HIGH)]
    decision = decide(findings, risk_score=60, policy=policy)
    assert decision == Decision.BLOCK  # instruction_override is block in the real default policy
