"""
Operator feedback endpoints.

Submitting feedback requires VIEWER: the people who notice a wrongful
block are the ones watching the dashboard, and making them ask an admin
to report it guarantees the reports never happen. Attaching original text
requires ADMIN, because that is a data-retention decision rather than an
observation.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from sentinelcore.core.auth import Role, require_role
from sentinelcore.services import feedback as fb

router = APIRouter()


class FeedbackIn(BaseModel):
    scan_id: str
    verdict: fb.Verdict
    note: str = ""
    submitted_by: str = Field("", description="UNVERIFIED; audit annotation, not an authenticated claim")


class TextIn(BaseModel):
    text: str = Field(..., description="The original input. Storing it is a retention decision.")


@router.post("/feedback", dependencies=[Depends(require_role(Role.VIEWER))])
def submit(body: FeedbackIn):
    fid = fb.submit(body.scan_id, body.verdict, body.note, body.submitted_by)
    if fid is None:
        raise HTTPException(status_code=503, detail="Feedback store unavailable.")
    return {"id": fid, "scan_id": body.scan_id, "verdict": body.verdict.value}


@router.post("/feedback/{feedback_id}/text", dependencies=[Depends(require_role(Role.ADMIN))])
def attach_text(feedback_id: str, body: TextIn):
    """Deliberately admin-only and deliberately a separate call: a security
    tool should not start retaining user input as a side effect of someone
    clicking 'this was wrong'."""
    if not fb.add_text(feedback_id, body.text):
        raise HTTPException(status_code=404, detail="No such feedback record.")
    return {"id": feedback_id, "text_supplied": True}


@router.get("/feedback", dependencies=[Depends(require_role(Role.VIEWER))])
def listing(verdict: fb.Verdict | None = None, limit: int = Query(default=100, ge=1, le=1000)):
    return {"feedback": fb.list_feedback(verdict, limit)}


@router.get("/feedback/summary", dependencies=[Depends(require_role(Role.VIEWER))])
def summary():
    return fb.summary()
