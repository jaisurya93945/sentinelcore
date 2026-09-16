"""
Operator feedback on security decisions.

WHY THIS IS MORE THAN A UI FEATURE
Finding 10 established that this project cannot measure over-defense: the
corpus contains 5 hard negatives out of 399 benign examples, so every
false-positive rate we report is an easy-negative rate. The published
NotInject results show this is where the strongest deployed detectors do
worst -- PromptGuard at 0.88% over-defense accuracy.

An operator marking a block as wrong is producing exactly the data that
gap needs: a benign input that a detector flagged, in production, on real
traffic. **The review queue is a hard-negative collector.** That is the
reason it is worth building before most of the rest of the dashboard.

WHAT IS STORED, AND WHAT IS NOT
A feedback record references an audit event by scan_id and carries a
verdict plus an optional note. It does NOT store the original text, for
the same reason the audit log does not -- see audit_log.py.

That creates a real limitation, stated rather than worked around: **the
exported cases carry no text, so they cannot be replayed directly.** To
build a regression corpus an operator must supply the text themselves,
consciously, via `add_text`. Making that an explicit act rather than a
silent default is the point: a security tool should not quietly begin
retaining user input because someone clicked a button.
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from enum import Enum

from sentinelcore.storage import get_store

logger = logging.getLogger(__name__)


class Verdict(str, Enum):
    FALSE_POSITIVE = "false_positive"   # we blocked something benign
    TRUE_POSITIVE = "true_positive"     # we were right
    FALSE_NEGATIVE = "false_negative"   # we allowed something malicious
    UNSURE = "unsure"


def init_db() -> None:
    try:
        get_store()
    except Exception as e:
        logger.warning(f"Feedback store init failed: {e}")


def submit(scan_id: str, verdict: Verdict, note: str = "", submitted_by: str = "") -> str | None:
    fid = str(uuid.uuid4())
    try:
        ok = get_store().write_feedback(fid, scan_id, verdict.value, note, submitted_by,
                                        datetime.now(timezone.utc).isoformat())
        return fid if ok else None
    except Exception as e:
        logger.warning(f"Feedback write failed: {e}")
        return None


def add_text(feedback_id: str, text: str) -> bool:
    """Attach the original input to a feedback record.

    Separate from submit() on purpose. Storing scanned text is a retention
    decision with real consequences, and it should require a deliberate
    second action by someone who knows what the text contains -- not be a
    side effect of clicking 'this was wrong'."""
    try:
        return get_store().attach_feedback_text(feedback_id, text)
    except Exception as e:
        logger.warning(f"Feedback text attach failed: {e}")
        return False


def list_feedback(verdict: Verdict | None = None, limit: int = 100) -> list[dict]:
    try:
        return get_store().list_feedback(verdict.value if verdict else None, limit)
    except Exception as e:
        logger.warning(f"Feedback read failed: {e}")
        return []


def summary() -> dict:
    try:
        counts = get_store().feedback_counts()
        total = sum(counts.values())
        fp = counts.get(Verdict.FALSE_POSITIVE.value, 0)
        fn = counts.get(Verdict.FALSE_NEGATIVE.value, 0)
        return {
            "counts": counts,
            "total": total,
            "reported_false_positive_share": round(fp / total, 4) if total else None,
            "reported_false_negative_share": round(fn / total, 4) if total else None,
            "caveat": (
                "Operator-reported and selection-biased: only reviewed decisions appear, "
                "and a wrongful block is far more likely to be reported than a wrongful allow. "
                "Not comparable to a measured FPR."
            ),
        }
    except Exception as e:
        logger.warning(f"Feedback summary failed: {e}")
        return {"counts": {}, "total": 0}


def export_hard_negatives(path: str) -> int:
    """Exports false-positive reports WITH supplied text as JSONL benign
    cases -- the hard negatives Finding 10 says the corpus lacks.

    Records without supplied text are skipped and counted, because a case
    with no text cannot be replayed and shipping it would pad the corpus
    with rows that look like data and are not."""
    rows = [r for r in list_feedback(Verdict.FALSE_POSITIVE, limit=10000) if r.get("text")]
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps({
                "id": f"operator-fp-{r['id'][:8]}",
                "text": r["text"],
                "label": "benign",
                "category": "operator_reported_false_positive",
                "source": "operator feedback",
                "language": "unspecified",
                "metadata": {"scan_id": r["scan_id"], "note": r["note"]},
            }, ensure_ascii=False) + "\n")
    return len(rows)
