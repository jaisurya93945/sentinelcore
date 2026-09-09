"""
Tests for the human approval workflow.

The property these exist to protect: HUMAN_APPROVAL must never be
reported as though a human approved something. Every non-approved state
-- pending, denied, expired, missing, store failure -- must refuse.
"""

import time

import pytest
from fastapi.testclient import TestClient

from sentinelcore.core.config import settings
from sentinelcore.main import app
from sentinelcore.services import approvals

client = TestClient(app)


def test_new_request_does_not_permit_execution():
    aid = approvals.request_approval("scan-1", "payment.transfer", "digest", 85)
    assert aid is not None
    assert approvals.permits_execution(aid) is False


def test_approval_permits_execution():
    aid = approvals.request_approval("scan-2", "payment.transfer", "d", 85)
    approvals.decide(aid, True, "ops@corp", "verified")
    assert approvals.permits_execution(aid) is True


def test_denial_refuses():
    aid = approvals.request_approval("scan-3", "payment.transfer", "d", 85)
    approvals.decide(aid, False, "ops@corp", "unrecognised recipient")
    assert approvals.permits_execution(aid) is False


def test_unknown_id_refuses():
    assert approvals.permits_execution("does-not-exist") is False


def test_expiry_is_a_refusal_not_consent(monkeypatch):
    """The single most important behaviour here: an operator being asleep
    must not authorise a privileged action."""
    monkeypatch.setattr(settings, "approval_ttl_seconds", 0)
    aid = approvals.request_approval("scan-4", "payment.transfer", "d", 90)
    time.sleep(0.01)
    assert approvals.permits_execution(aid) is False
    assert approvals.get_approval(aid)["status"] == "expired"


def test_expired_cannot_be_revived_by_late_approval(monkeypatch):
    monkeypatch.setattr(settings, "approval_ttl_seconds", 0)
    aid = approvals.request_approval("scan-5", "payment.transfer", "d", 90)
    time.sleep(0.01)
    approvals.decide(aid, True, "late@corp", "sorry, was asleep")
    assert approvals.permits_execution(aid) is False


def test_decision_is_not_reversible():
    aid = approvals.request_approval("scan-6", "payment.transfer", "d", 85)
    approvals.decide(aid, False, "ops@corp")
    approvals.decide(aid, True, "someone-else@corp")
    assert approvals.permits_execution(aid) is False


def test_tool_call_returns_an_approval_id():
    r = client.post("/api/v1/scan/tool-call",
                    json={"tool_name": "payment.transfer", "arguments": {"amount": 500}})
    assert r.status_code == 200
    body = r.json()
    assert body["decision"] == "human_approval"
    assert body["approval_id"]
    assert body["enforcement_status"] == "pending_approval"
    assert approvals.permits_execution(body["approval_id"]) is False


def test_end_to_end_approval_flow():
    created = client.post("/api/v1/scan/tool-call",
                          json={"tool_name": "payment.transfer", "arguments": {"amount": 10}}).json()
    aid = created["approval_id"]

    listed = client.get("/api/v1/approvals/pending").json()["approvals"]
    assert any(a["id"] == aid for a in listed)

    decided = client.post(f"/api/v1/approvals/{aid}/decide",
                          json={"approved": True, "decided_by": "ops@corp", "reason": "ok"})
    assert decided.status_code == 200
    assert decided.json()["status"] == "approved"
    assert approvals.permits_execution(aid) is True


def test_deciding_twice_is_a_conflict():
    created = client.post("/api/v1/scan/tool-call",
                          json={"tool_name": "payment.transfer", "arguments": {"amount": 10}}).json()
    aid = created["approval_id"]
    client.post(f"/api/v1/approvals/{aid}/decide", json={"approved": True, "decided_by": "a"})
    second = client.post(f"/api/v1/approvals/{aid}/decide", json={"approved": False, "decided_by": "b"})
    assert second.status_code == 409


def test_unknown_approval_returns_404():
    assert client.get("/api/v1/approvals/nope").status_code == 404


def test_deciding_requires_admin_role(monkeypatch):
    """Separation of duty: the role that triggers actions must not be the
    role that authorises them, or the control is decorative."""
    created = client.post("/api/v1/scan/tool-call",
                          json={"tool_name": "payment.transfer", "arguments": {"amount": 10}}).json()
    aid = created["approval_id"]
    monkeypatch.setattr(settings, "api_keys", "opkey:operator,adminkey:admin")

    denied = client.post(f"/api/v1/approvals/{aid}/decide",
                         json={"approved": True, "decided_by": "x"}, headers={"X-API-Key": "opkey"})
    assert denied.status_code == 403

    allowed = client.post(f"/api/v1/approvals/{aid}/decide",
                          json={"approved": True, "decided_by": "x"}, headers={"X-API-Key": "adminkey"})
    assert allowed.status_code == 200


def test_non_approval_decisions_have_no_approval_id():
    r = client.post("/api/v1/scan/tool-call",
                    json={"tool_name": "web.search", "arguments": {"q": "x"}}).json()
    assert r["decision"] == "allow"
    assert r["approval_id"] is None


def test_decide_reports_whether_it_actually_applied():
    """Regression: decide() originally returned only the record, so an
    already-decided approval was indistinguishable from a fresh decision
    and the endpoint returned 200 for a decision that never took effect.
    An operator could believe they had denied something that is approved."""
    aid = approvals.request_approval("scan-applied", "payment.transfer", "d", 85)

    record, applied = approvals.decide(aid, True, "first@corp")
    assert applied is True and record["status"] == "approved"

    record2, applied2 = approvals.decide(aid, False, "second@corp")
    assert applied2 is False, "a second decision must report that it did not apply"
    assert record2["status"] == "approved", "the original decision must stand"
    assert approvals.permits_execution(aid) is True
