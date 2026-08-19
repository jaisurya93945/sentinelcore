"""
Security finding schema.

Every detector returns a list of `Finding` objects. The gateway aggregates
them into a `ScanResult`. This schema is intentionally simple in v0.1 -- it
will evolve as the risk engine and policy engine are implemented (Phase 3).
"""

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Decision(str, Enum):
    ALLOW = "allow"
    WARN = "warn"
    SANITIZE = "sanitize"
    HUMAN_APPROVAL = "human_approval"
    BLOCK = "block"


class Finding(BaseModel):
    """A single security finding produced by one detector."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    detector: str = Field(..., description="Name of the detector that produced this finding")
    type: str = Field(..., description="Finding category, e.g. 'prompt_injection'")
    description: str
    severity: Severity
    confidence: float | None = Field(
        default=None,
        description=(
            "Only set if the underlying detector is calibrated. "
            "Never fabricated -- see project Authenticity Policy."
        ),
    )
    origin: str = Field(
        default="input",
        description=(
            "Where this finding was found: 'input' for the main text, "
            "'context:<index>' for the Nth retrieved/RAG document, "
            "'output' for the LLM's response, or 'tool_arguments'/"
            "'tool_response' for agent tool-call scanning"
        ),
    )
    evidence: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScanResult(BaseModel):
    """Aggregate result of running all registered detectors against one input."""

    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    input_text: str
    findings: list[Finding] = Field(default_factory=list)
    risk_score: int | None = Field(
        default=None,
        ge=0,
        le=100,
        description="Set by the risk engine (Phase 3, not yet implemented)",
    )
    decision: Decision | None = Field(
        default=None,
        description="Set by the policy engine (Phase 3, not yet implemented)",
    )


class ScanRequest(BaseModel):
    """Request body for POST /api/v1/scan."""

    text: str
    context: dict[str, Any] | None = None
    retrieved_documents: list[str] | None = Field(
        default=None,
        description=(
            "RAG-retrieved documents to also scan for indirect prompt injection, "
            "in addition to the main input text. Each finding from these is "
            "tagged origin='context:<index>' to distinguish it from the user's own words."
        ),
    )
    output_text: str | None = Field(
        default=None,
        description=(
            "A candidate LLM response to scan before it's sent to a user or "
            "downstream system -- e.g. PII or secret leakage. Findings are "
            "tagged origin='output'. Optional; omit for input-only scanning."
        ),
    )


class ToolCallRequest(BaseModel):
    """Request body for POST /api/v1/scan/tool-call."""

    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    response: str | None = Field(
        default=None,
        description=(
            "The tool's response, if it has already been executed. Scanned as "
            "untrusted input -- exactly the same principle as retrieved_documents "
            "on /api/v1/scan: a tool response is not automatically trustworthy "
            "just because your own agent called the tool."
        ),
    )


class ToolCallResult(BaseModel):
    """Response body for POST /api/v1/scan/tool-call."""

    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tool_name: str
    tool_authorization: Decision = Field(
        description="Deterministic allow/warn/sanitize/human_approval/block lookup by tool name -- independent of content scanning."
    )
    findings: list[Finding] = Field(default_factory=list)
    risk_score: int = 0
    decision: Decision = Field(
        default=Decision.ALLOW,
        description="The more severe of tool_authorization and the content-scanning decision.",
    )
