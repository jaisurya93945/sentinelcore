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
