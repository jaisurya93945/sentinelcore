"""Unit tests for the audit log."""

from app.models.finding import Finding, Severity
from app.services.audit_log import get_recent_events, log_scan_event


def _finding(type_="test_type", severity=Severity.LOW, origin="input"):
    f = Finding(detector="test", type=type_, description="test", severity=severity)
    f.origin = origin
    return f


def test_log_and_retrieve_event():
    log_scan_event("scan-1", "scan", 10, "warn", [_finding()])
    events = get_recent_events(limit=10)
    assert len(events) >= 1
    assert events[0]["scan_id"] == "scan-1"
    assert events[0]["decision"] == "warn"
    assert events[0]["risk_score"] == 10
    assert events[0]["finding_count"] == 1


def test_findings_summary_has_no_evidence_or_raw_text():
    log_scan_event("scan-2", "scan", 90, "block", [_finding(type_="aws_access_key", severity=Severity.CRITICAL)])
    events = get_recent_events(limit=10)
    event = next(e for e in events if e["scan_id"] == "scan-2")
    assert "evidence" not in event["findings"][0]
    assert set(event["findings"][0].keys()) == {"type", "severity", "origin", "detector"}


def test_recent_events_ordered_newest_first():
    log_scan_event("scan-a", "scan", 0, "allow", [])
    log_scan_event("scan-b", "scan", 0, "allow", [])
    events = get_recent_events(limit=2)
    assert events[0]["scan_id"] == "scan-b"
    assert events[1]["scan_id"] == "scan-a"


def test_logging_failure_never_raises(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "audit_db_path", "/nonexistent-dir-xyz/cannot-write.db")
    log_scan_event("scan-fail", "scan", 0, "allow", [])  # must not raise


def test_disabled_audit_is_a_no_op(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "audit_enabled", False)
    log_scan_event("scan-disabled", "scan", 0, "allow", [])
    assert get_recent_events(limit=100) == []


def test_detail_field_stored_and_retrieved():
    log_scan_event("scan-detail", "tool_call", 0, "block", [], detail="database.delete")
    events = get_recent_events(limit=10)
    event = next(e for e in events if e["scan_id"] == "scan-detail")
    assert event["detail"] == "database.delete"


def test_detail_defaults_to_none():
    log_scan_event("scan-nodetail", "scan", 0, "allow", [])
    events = get_recent_events(limit=10)
    event = next(e for e in events if e["scan_id"] == "scan-nodetail")
    assert event["detail"] is None
