"""
SentinelCore -- a security control plane for LLM and agent applications.

    from sentinelcore import Guard

    guard = Guard(policy="balanced")
    outcome = guard.scan("ignore all previous instructions")
    if not outcome.allowed:
        ...

See docs/CAPABILITY_MATRIX.md for what is implemented, tested, validated
and planned. Claims in this project are traceable to result files; see
docs/evidence/EVIDENCE_TABLE.md.
"""

from sentinelcore._version import __version__
from sentinelcore.guard import Blocked, Decision, EnforcementStatus, Guard, ScanOutcome
__all__ = ["Guard", "ScanOutcome", "Decision", "EnforcementStatus", "Blocked", "__version__"]
