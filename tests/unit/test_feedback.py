"""
Tests for operator feedback.

The property that matters most: feedback must not become a silent
text-retention channel. Reporting a wrongful block is an observation;
storing the input that caused it is a retention decision, and the two are
deliberately separate calls with different required roles.
"""

import json
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient

from sentinelcore.core.config import settings
from sentinelcore.main import app
from sentinelcore.services import feedback as fb

client = TestClient(app)


def test_submit_and_list():
    fid = fb.submit("scan-1", fb.Verdict.FALSE_POSITIVE, "user asked what injection is", "ops")
    assert fid
    rows = fb.list_feedback(fb.Verdict.FALSE_POSITIVE)
    assert any(r["id"] == fid for r in rows)


def test_text_is_not_stored_by_default():
    """The core privacy property: submitting feedback must never retain
    the scanned input as a side effect."""
    fid = fb.submit("scan-2", fb.Verdict.FALSE_POSITIVE)
    row = next(r for r in fb.list_feedback() if r["id"] == fid)
    assert row["text"] is None
    assert row["text_supplied"] == 0


def test_text_attaches_only_on_an_explicit_second_call():
    fid = fb.submit("scan-3", fb.Verdict.FALSE_POSITIVE)
    assert fb.add_text(fid, "What is prompt injection?")
    row = next(r for r in fb.list_feedback() if r["id"] == fid)
    assert row["text"] == "What is prompt injection?" and row["text_supplied"] == 1


def test_attach_to_unknown_record_fails():
    assert fb.add_text("no-such-id", "x") is False


def test_summary_carries_its_selection_bias_caveat():
    """Reported rates are not measured rates, and the API must say so --
    a dashboard number without this caveat will be quoted as an FPR."""
    fb.submit("scan-4", fb.Verdict.FALSE_POSITIVE)
    s = fb.summary()
    assert s["total"] >= 1
    assert "selection-biased" in s["caveat"]
    assert "Not comparable to a measured FPR" in s["caveat"]


def test_export_produces_eval_set_schema():
    """The point of the queue: operator false positives become the hard
    negatives Finding 10 says the corpus lacks."""
    fid = fb.submit("scan-5", fb.Verdict.FALSE_POSITIVE, "legitimate security question")
    fb.add_text(fid, "Explain how prompt injection attacks work")
    with tempfile.TemporaryDirectory() as d:
        out = Path(d) / "hn.jsonl"
        n = fb.export_hard_negatives(str(out))
        assert n >= 1
        rec = json.loads(out.read_text().splitlines()[0])
        assert set(rec) >= {"id", "text", "label", "category", "source"}
        assert rec["label"] == "benign"


def test_export_skips_records_without_text():
    """A case with no text cannot be replayed; exporting it would pad the
    corpus with rows that look like data and are not."""
    fb.submit("scan-6", fb.Verdict.FALSE_POSITIVE)  # no text attached
    with tempfile.TemporaryDirectory() as d:
        out = Path(d) / "hn.jsonl"
        n = fb.export_hard_negatives(str(out))
        exported_ids = [json.loads(l)["metadata"]["scan_id"] for l in out.read_text().splitlines()]
    assert "scan-6" not in exported_ids


# --- API contract ---

def test_api_submit_and_summary():
    r = client.post("/api/v1/feedback", json={"scan_id": "s", "verdict": "false_positive", "note": "n"})
    assert r.status_code == 200 and r.json()["id"]
    assert client.get("/api/v1/feedback/summary").status_code == 200


def test_attaching_text_requires_admin(monkeypatch):
    fid = client.post("/api/v1/feedback", json={"scan_id": "s", "verdict": "false_positive"}).json()["id"]
    monkeypatch.setattr(settings, "api_keys", "v:viewer,a:admin")

    denied = client.post(f"/api/v1/feedback/{fid}/text", json={"text": "x"}, headers={"X-API-Key": "v"})
    assert denied.status_code == 403, "retention must not be a viewer-level action"

    ok = client.post(f"/api/v1/feedback/{fid}/text", json={"text": "x"}, headers={"X-API-Key": "a"})
    assert ok.status_code == 200


def test_submitting_feedback_is_viewer_level(monkeypatch):
    """The people who notice a wrongful block are watching the dashboard.
    Requiring admin to report one guarantees it never gets reported."""
    monkeypatch.setattr(settings, "api_keys", "v:viewer")
    r = client.post("/api/v1/feedback", json={"scan_id": "s", "verdict": "false_positive"},
                    headers={"X-API-Key": "v"})
    assert r.status_code == 200


def test_attach_text_to_missing_record_returns_404():
    assert client.post("/api/v1/feedback/nope/text", json={"text": "x"}).status_code == 404
