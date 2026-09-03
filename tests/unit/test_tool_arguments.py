"""Unit tests for the tool argument detector."""

from app.detectors.registry import get_registered_detectors
from app.detectors.tool_arguments.detector import ToolArgumentDetector


def test_detector_is_registered():
    assert "tool_arguments" in get_registered_detectors()


def test_benign_arguments_no_findings():
    detector = ToolArgumentDetector()
    benign = [
        '{"query": "capital of France"}',
        '{"filename": "report.pdf"}',
        '{"user_id": 42}',
    ]
    for text in benign:
        assert detector.detect(text) == [], f"False positive on: {text!r}"


def test_sql_drop_table_detected():
    findings = ToolArgumentDetector().detect('{"query": "DROP TABLE users;"}')
    assert any(f.type == "sql_injection_pattern" for f in findings)


def test_sql_tautology_detected():
    findings = ToolArgumentDetector().detect("SELECT * FROM users WHERE username='admin' OR 1=1")
    assert any(f.type == "sql_injection_pattern" for f in findings)


def test_shell_destructive_command_detected():
    findings = ToolArgumentDetector().detect('{"command": "rm -rf /"}')
    matches = [f for f in findings if f.type == "shell_injection_pattern"]
    assert len(matches) >= 1
    assert any(f.severity.value == "critical" for f in matches)


def test_shell_command_substitution_detected():
    findings = ToolArgumentDetector().detect('{"arg": "$(whoami)"}')
    assert any(f.type == "shell_injection_pattern" for f in findings)


def test_path_traversal_detected():
    findings = ToolArgumentDetector().detect('{"path": "../../../../etc/passwd"}')
    types = {f.type for f in findings}
    assert "path_traversal" in types


def test_never_returns_none_on_empty_input():
    result = ToolArgumentDetector().detect("")
    assert result == []
    assert isinstance(result, list)
