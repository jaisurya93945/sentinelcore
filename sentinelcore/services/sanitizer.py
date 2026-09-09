"""
Real sanitization enforcement.

Until this module existed, SANITIZE was a decision the policy engine
could return with nothing behind it -- returned, displayed, never
executed. That's exactly the gap this module closes: strip or normalize
the specific characters/patterns a finding flagged, then RE-SCAN the
cleaned text before calling it safe.

The re-scan is the actual point, not a formality. Collapsing
"I g n o r e   a l l   i n s t r u c t i o n s" (character_spacing_evasion)
reveals "Ignore all instructions" underneath -- a real instruction
override -- and that has to be caught on the cleaned text, not silently
allowed through just because the surface-level spacing trick was fixed.
If cleaning reveals something the policy engine would still flag, the
result is ESCALATED, not ENFORCED.
"""

from sentinelcore.detectors.obfuscation.patterns import BIDI_CONTROL_CHARS, UNUSUAL_SPACE_CHARS, ZERO_WIDTH_CHARS
from sentinelcore.detectors.registry import get_registered_detectors
from sentinelcore.models.finding import Decision, EnforcementStatus, Finding
from sentinelcore.services.policy_engine import decide
from sentinelcore.services.risk_engine import calculate_risk_score


def _strip_zero_width(text: str) -> str:
    for ch in ZERO_WIDTH_CHARS:
        text = text.replace(ch, "")
    return text


def _strip_bidi_controls(text: str) -> str:
    for ch in BIDI_CONTROL_CHARS:
        text = text.replace(ch, "")
    return text


def _normalize_unusual_whitespace(text: str) -> str:
    for ch in UNUSUAL_SPACE_CHARS:
        text = text.replace(ch, " ")
    return text


def _strip_control_characters(text: str) -> str:
    allowed = {"\t", "\n", "\r"}
    return "".join(ch for ch in text if not (ord(ch) < 0x20 and ch not in allowed))


def _collapse_character_spacing(text: str, min_run: int = 5) -> str:
    """Reverses character_spacing_evasion: runs of >= min_run single-
    character tokens get joined back into a word, matching the same
    threshold the detector itself uses to flag them."""
    tokens = text.split()
    out: list[str] = []
    i, n = 0, len(tokens)
    while i < n:
        if len(tokens[i]) == 1:
            start = i
            while i < n and len(tokens[i]) == 1:
                i += 1
            if i - start >= min_run:
                out.append("".join(tokens[start:i]))
            else:
                out.extend(tokens[start:i])
        else:
            out.append(tokens[i])
            i += 1
    return " ".join(out)


# Only finding types with a real, well-defined, reversible transform are
# here. character_spacing_evasion is included because collapsing spaced-
# out text IS a well-defined transform -- what happens to the result is
# handled by the mandatory re-scan below, not by this function pretending
# to know whether the revealed text is safe.
_SANITIZERS = {
    "zero_width_characters": _strip_zero_width,
    "bidi_control_characters": _strip_bidi_controls,
    "unusual_whitespace": _normalize_unusual_whitespace,
    "control_characters": _strip_control_characters,
    "character_spacing_evasion": _collapse_character_spacing,
}


class SanitizeResult:
    def __init__(
        self,
        sanitized_text: str,
        findings: list[Finding],
        risk_score: int,
        decision: Decision,
        enforcement_status: EnforcementStatus,
    ):
        self.sanitized_text = sanitized_text
        self.findings = findings
        self.risk_score = risk_score
        self.decision = decision
        self.enforcement_status = enforcement_status


def enforce_sanitize(text: str, findings: list[Finding]) -> SanitizeResult:
    """
    Applies every applicable sanitizer for the finding types present in
    `findings`, re-scans the result with the full detector pipeline, and
    returns the final (possibly escalated) outcome. Never returns a
    decision of SANITIZE alongside unscanned "cleaned" text.
    """
    finding_types = {f.type for f in findings}
    applicable = [t for t in finding_types if t in _SANITIZERS]

    if not applicable:
        return SanitizeResult(text, findings, calculate_risk_score(findings), Decision.SANITIZE, EnforcementStatus.NOT_IMPLEMENTED)

    cleaned = text
    for type_name, fn in _SANITIZERS.items():
        if type_name in finding_types:
            cleaned = fn(cleaned)

    new_findings: list[Finding] = []
    for cls in get_registered_detectors().values():
        new_findings.extend(cls().detect(cleaned))

    new_risk_score = calculate_risk_score(new_findings)
    new_decision = decide(new_findings, new_risk_score)

    if new_decision in (Decision.ALLOW, Decision.WARN):
        return SanitizeResult(cleaned, new_findings, new_risk_score, new_decision, EnforcementStatus.ENFORCED)

    # Cleaning revealed something the policy engine still flags --
    # escalate to that real decision, not the original SANITIZE label.
    return SanitizeResult(cleaned, new_findings, new_risk_score, new_decision, EnforcementStatus.ESCALATED)
