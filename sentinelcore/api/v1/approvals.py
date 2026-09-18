"""
Human approval endpoints.

Deciding an approval is an ADMIN-role operation, not operator: the entire
point of HUMAN_APPROVAL is that the party who triggered the action is not
the party who authorises it. Granting approval rights to the same role
that calls the scan endpoints would collapse that separation and make the
control decorative.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from sentinelcore.core.auth import Role, require_role
from sentinelcore.services import approvals

router = APIRouter()


class ApprovalDecision(BaseModel):
    approved: bool
    decided_by: str = Field(
        "",
        description=(
            "IGNORED. The deciding principal is taken from the authenticated "
            "credential, not from the request body. Previously this was a "
            "self-asserted string, which meant the audit trail recorded a claim "
            "rather than a fact -- and an approval record whose 'who' can be "
            "forged is not an approval record. Kept in the schema so existing "
            "callers do not break."
        ),
    )
    reason: str = ""


@router.get("/approvals/pending", dependencies=[Depends(require_role(Role.VIEWER))])
def pending(limit: int = Query(default=50, ge=1, le=500)):
    return {"approvals": approvals.list_pending(limit=limit)}


@router.get("/approvals/{approval_id}", dependencies=[Depends(require_role(Role.VIEWER))])
def get_one(approval_id: str):
    record = approvals.get_approval(approval_id)
    if record is None:
        raise HTTPException(status_code=404, detail="No such approval.")
    return record


@router.post("/approvals/{approval_id}/decide", dependencies=[Depends(require_role(Role.ADMIN))])
def decide(approval_id: str, decision: ApprovalDecision):
    from sentinelcore.core.identity import current

    # Authenticated identity wins over anything the caller claims.
    record, applied = approvals.decide(
        approval_id, decision.approved, current().principal_id, decision.reason
    )
    if record is None:
        raise HTTPException(status_code=404, detail="No such approval.")
    if not applied:
        # Already terminal -- expired, or decided by someone else first.
        # Reported as a conflict rather than returning 200 for a decision
        # that did not take effect, which would let an operator believe
        # they had denied something that is actually approved.
        raise HTTPException(
            status_code=409,
            detail=f"Approval is already {record['status']}; this decision was not applied.",
        )
    return record
