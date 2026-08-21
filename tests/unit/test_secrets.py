"""Unit tests for the secret/credential detector."""

from app.detectors.registry import get_registered_detectors
from app.detectors.secrets.detector import SecretDetector


def test_detector_is_registered():
    assert "secrets" in get_registered_detectors()


def test_benign_text_produces_no_findings():
    detector = SecretDetector()
    benign_examples = [
        "What's the weather like in Chennai today?",
        "Please review my pull request when you get a chance.",
        "The API returned a 200 status code.",
    ]
    for text in benign_examples:
        assert detector.detect(text) == [], f"False positive on: {text!r}"


def test_aws_access_key_detected():
    # AWS's own published example key, safe to use as a test fixture --
    # not a real credential (https://docs.aws.amazon.com uses this exact
    # string as its documentation placeholder).
    findings = SecretDetector().detect("Here is the key: AKIAIOSFODNN7EXAMPLE")
    matches = [f for f in findings if f.type == "aws_access_key"]
    assert len(matches) == 1
    assert matches[0].severity.value == "critical"


def test_private_key_block_detected():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
    findings = SecretDetector().detect(text)
    assert any(f.type == "private_key" for f in findings)


def test_generic_api_key_assignment_detected():
    fake_key = "sk_" + "liv" + "e_" + "abcdefghijklmnopqrstuvwx"
    findings = SecretDetector().detect(f'api_key = "{fake_key}"')
    assert any(f.type == "generic_api_key" for f in findings)


def test_db_connection_string_detected():
    findings = SecretDetector().detect("Connect via postgres://admin:hunter2@db.internal:5432/prod")
    assert any(f.type == "db_connection_string" for f in findings)


def test_matched_text_is_redacted_not_raw():
    findings = SecretDetector().detect("Here is the key: AKIAIOSFODNN7EXAMPLE")
    finding = next(f for f in findings if f.type == "aws_access_key")
    assert "AKIAIOSFODNN7EXAMPLE" not in finding.evidence["matched_text"]
    assert "*" in finding.evidence["matched_text"]


def test_never_returns_none_on_empty_input():
    result = SecretDetector().detect("")
    assert result == []
    assert isinstance(result, list)
