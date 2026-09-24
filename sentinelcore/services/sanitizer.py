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

import re
from sentinelcore.detectors.obfuscation.patterns import BIDI_CONTROL_CHARS, UNUSUAL_SPACE_CHARS, ZERO_WIDTH_CHARS
from sentinelcore.detectors.registry import get_registered_detectors
from sentinelcore.models.finding import Decision, EnforcementStatus, Finding
from sentinelcore.services.policy_engine import decide
from sentinelcore.services.risk_engine import calculate_risk_score
from sentinelcore.core.textextract import extract_scannable_text, map_strings


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
    threshold the detector itself uses to flag them.

    WORD BOUNDARIES ARE PRESERVED, and that is the whole difficulty.

    This used to begin `tokens = text.split()`, which throws away how much
    whitespace separated each token. Attackers space words apart with a
    wider gap than they space letters, so that distinction is the only
    thing marking where one word ends:

        "i g n o r e   a l l   p r e v i o u s"
                    ^^^ three spaces: a word boundary
         ^ one space: a letter boundary

    Having discarded it, every single-character token joined into one run
    and the result was `ignoreallpreviousinstructions` -- which no
    detector matches. The sanitizer therefore reported ENFORCED, handed
    back text that still carried the attack, and the mandatory re-scan
    found nothing to escalate. Cleaning turned a detectable attack into an
    undetectable one.

    So: a gap of two or more whitespace characters between single-char
    tokens ends the word. Each sub-run is joined separately and the words
    are rejoined with single spaces, giving `ignore all previous
    instructions`, which the rules engine matches on the re-scan.
    """
    # (token, whitespace that followed it). Keeping the separator is the fix.
    parts = re.findall(r"(\S+)(\s*)", text)
    if not parts:
        return text

    out: list[str] = []
    i, n = 0, len(parts)
    while i < n:
        tok, _ = parts[i]
        if len(tok) != 1:
            out.append(tok)
            i += 1
            continue

        # A maximal run of single-character tokens, split into words
        # wherever the gap widens to 2+ whitespace characters.
        start = i
        words: list[list[str]] = [[]]
        while i < n and len(parts[i][0]) == 1:
            words[-1].append(parts[i][0])
            gap = parts[i][1]
            i += 1
            if i < n and len(parts[i][0]) == 1 and len(gap) >= 2:
                words.append([])

        if i - start >= min_run:
            out.extend("".join(w) for w in words if w)
        else:
            out.extend(t for t, _ in parts[start:i])

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


class SanitizeArgumentsResult:
    """What actually happened to a structured tool argument."""

    def __init__(self, sanitized_arguments, findings, risk_score, decision, enforcement_status):
        self.sanitized_arguments = sanitized_arguments
        self.findings = findings
        self.risk_score = risk_score
        self.decision = decision
        self.enforcement_status = enforcement_status


def enforce_sanitize_arguments(arguments: dict, findings: list[Finding]) -> SanitizeArgumentsResult:
    """SANITIZE for structured tool arguments.

    The tool-call path used to act on HUMAN_APPROVAL and ignore SANITIZE
    entirely: it returned `decision: sanitize` with no sanitized output and
    `enforcement_status` left at NOT_APPLICABLE. A caller doing what the
    response said -- sanitize, then proceed -- had nothing to proceed with,
    and a caller treating "not BLOCK" as permission forwarded the original
    arguments untouched. That is precisely the "decision reported as
    completed action" failure EnforcementStatus exists to prevent, on the
    path this project weights as most dangerous.

    The reason it was skipped is real: the sanitizers take text, and tool
    arguments are a nested structure, so there was nothing to hand back.
    `map_strings` rebuilds the structure with each string cleaned.

    Same contract as `enforce_sanitize`, and for the same reason: the
    cleaned arguments are RE-SCANNED with the full pipeline, and if the
    policy still objects the decision escalates rather than being reported
    as a successful sanitize. Cleaning can also reveal an attack that the
    obfuscation was hiding -- collapsing "i g n o r e" yields "ignore" --
    so a re-scan is not a formality.
    """
    finding_types = {f.type for f in findings}
    applicable = [t for t in finding_types if t in _SANITIZERS]

    if not applicable:
        # SANITIZE was asked for and nothing here can carry it out -- most
        # often because it came from the tool-NAME policy rather than
        # content. Say so; callers must treat this as refusal.
        return SanitizeArgumentsResult(
            arguments, findings, calculate_risk_score(findings),
            Decision.SANITIZE, EnforcementStatus.NOT_IMPLEMENTED,
        )

    def clean(text: str) -> str:
        for type_name, fn in _SANITIZERS.items():
            if type_name in finding_types:
                text = fn(text)
        return text

    cleaned_args = map_strings(arguments, clean)

    new_findings: list[Finding] = []
    for cls in get_registered_detectors().values():
        for f in cls().detect(extract_scannable_text(cleaned_args)):
            f.origin = "tool_arguments"
            new_findings.append(f)

    new_risk = calculate_risk_score(new_findings)
    new_decision = decide(new_findings, new_risk)

    status = (EnforcementStatus.ENFORCED
              if new_decision in (Decision.ALLOW, Decision.WARN)
              else EnforcementStatus.ESCALATED)
    return SanitizeArgumentsResult(cleaned_args, new_findings, new_risk, new_decision, status)
