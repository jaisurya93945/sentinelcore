"""Unit tests for the PII detector."""

from app.detectors.pii.detector import PIIDetector
from app.detectors.registry import get_registered_detectors


def test_detector_is_registered():
    assert "pii" in get_registered_detectors()


def test_benign_text_produces_no_findings():
    detector = PIIDetector()
    benign_examples = [
        "What's the weather like in Chennai today?",
        "Can you help me write a Python function?",
        "The meeting is scheduled for next Tuesday.",
    ]
    for text in benign_examples:
        assert detector.detect(text) == [], f"False positive on: {text!r}"


def test_email_detected():
    findings = PIIDetector().detect("Contact me at john.doe@example.com for details.")
    assert any(f.type == "email_address" for f in findings)


def test_phone_number_detected():
    findings = PIIDetector().detect("Call me at 555-123-4567 tomorrow.")
    assert any(f.type == "phone_number" for f in findings)


def test_ssn_detected():
    findings = PIIDetector().detect("SSN on file: 123-45-6789")
    matches = [f for f in findings if f.type == "ssn"]
    assert len(matches) == 1
    assert matches[0].severity.value == "high"


def test_credit_card_detected():
    findings = PIIDetector().detect("Card number: 4111-1111-1111-1111")
    assert any(f.type == "credit_card" for f in findings)


def test_matched_text_is_redacted_not_raw():
    findings = PIIDetector().detect("Contact me at john.doe@example.com")
    finding = next(f for f in findings if f.type == "email_address")
    assert "john.doe@example.com" not in finding.evidence["matched_text"]
    assert "*" in finding.evidence["matched_text"]
    # First/last two characters preserved for identification, nothing more.
    assert finding.evidence["matched_text"].startswith("jo")
    assert finding.evidence["matched_text"].endswith("om")


def test_never_returns_none_on_empty_input():
    result = PIIDetector().detect("")
    assert result == []
    assert isinstance(result, list)
