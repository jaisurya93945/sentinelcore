"""
Pattern definitions for the prompt injection baseline detector.

Deliberately simple and transparent: regex/heuristic rules, not ML. This is
the v0.1 baseline (roadmap Phase 2). Known limitation -- documented, not
hidden: regex matching on phrasing produces false positives on legitimate
text that discusses these phrases, and false negatives on any attacker who
paraphrases or obfuscates around the exact wording. See
docs/threat-model/README.md for the full limitations list.
"""

import re
from dataclasses import dataclass

from app.models.finding import Severity


@dataclass(frozen=True)
class PatternRule:
    id: str
    category: str  # "instruction_override" | "system_prompt_extraction" | "role_manipulation"
    pattern: re.Pattern
    severity: Severity
    description: str


def _p(text: str) -> re.Pattern:
    return re.compile(text, re.IGNORECASE)


PATTERNS: list[PatternRule] = [
    # -- Instruction override ------------------------------------------------
    PatternRule(
        id="IO-001",
        category="instruction_override",
        pattern=_p(r"\bignore\s+(all\s+|any\s+)?(the\s+above|the\s+previous|the\s+prior|previous|prior|above|the)\s+instructions?\b"),
        severity=Severity.HIGH,
        description="Attempts to make the model ignore prior instructions",
    ),
    PatternRule(
        id="IO-002",
        category="instruction_override",
        pattern=_p(r"\bdisregard\s+(all\s+|any\s+)?(previous|prior|above|the)\s+(instructions?|rules?)\b"),
        severity=Severity.HIGH,
        description="Attempts to make the model disregard prior instructions or rules",
    ),
    PatternRule(
        id="IO-003",
        category="instruction_override",
        pattern=_p(r"\bforget\s+(everything|all|your\s+instructions|what\s+(i|you)\s+(said|told\s+you))\b"),
        severity=Severity.MEDIUM,
        description="Attempts to make the model forget prior context or instructions",
    ),
    PatternRule(
        id="IO-004",
        category="instruction_override",
        pattern=_p(r"\bnew\s+instructions?\s*:"),
        severity=Severity.MEDIUM,
        description="Introduces unauthorized 'new instructions' into the input",
    ),
    PatternRule(
        id="IO-005",
        category="instruction_override",
        pattern=_p(r"\boverride\s+(your|the)\s+(system\s+prompt|previous\s+instructions?|rules?)\b"),
        severity=Severity.HIGH,
        description="Explicit attempt to override system-level instructions",
    ),
    PatternRule(
        id="IO-006",
        category="instruction_override",
        pattern=_p(r"\bdo\s+not\s+follow\s+(your|the)\s+(previous|original)\s+instructions?\b"),
        severity=Severity.HIGH,
        description="Direct instruction to abandon original instructions",
    ),
    PatternRule(
        id="IO-007",
        category="instruction_override",
        pattern=_p(r"\bforget\s+about\s+(all|everything|the\s+previous)\b"),
        severity=Severity.MEDIUM,
        description="Attempts to make the model forget prior context, 'forget about' phrasing variant",
    ),
    # -- System prompt extraction ---------------------------------------------
    PatternRule(
        id="SE-001",
        category="system_prompt_extraction",
        pattern=_p(r"\brepeat\s+(your|the)\s+(system\s+prompt|instructions?|initial\s+prompt)\b"),
        severity=Severity.MEDIUM,
        description="Attempts to extract the system prompt verbatim",
    ),
    PatternRule(
        id="SE-002",
        category="system_prompt_extraction",
        pattern=_p(r"\bwhat\s+(is|are)\s+your\s+(system\s+prompt|instructions?|initial\s+prompt|guidelines?)\b"),
        severity=Severity.LOW,
        description="Asks the model to reveal its system prompt or instructions",
    ),
    PatternRule(
        id="SE-003",
        category="system_prompt_extraction",
        pattern=_p(r"\b(print|output|show|reveal|display)\s+(your|the)\s+(system\s+prompt|instructions?|configuration)\b"),
        severity=Severity.MEDIUM,
        description="Attempts to make the model print its configuration or instructions",
    ),
    PatternRule(
        id="SE-004",
        category="system_prompt_extraction",
        pattern=_p(r"\b(everything|all\s+text)\s+(above|before)\s+this\s+(line|point|message)\b"),
        severity=Severity.MEDIUM,
        description="Attempts to make the model output all preceding context, including system text",
    ),
    # -- Role manipulation / jailbreak framing --------------------------------
    PatternRule(
        id="RM-001",
        category="role_manipulation",
        pattern=_p(r"\byou\s+are\s+now\s+(DAN|unrestricted|jailbroken|free\s+from)\b"),
        severity=Severity.HIGH,
        description="Classic 'you are now [jailbreak persona]' framing",
    ),
    PatternRule(
        id="RM-002",
        category="role_manipulation",
        pattern=_p(
            r"\bpretend\s+(you|that\s+you)\s+(have\s+no|don't\s+have|do\s+not\s+have)\s+"
            r"(restrictions?|rules?|filters?|guidelines?)\b"
        ),
        severity=Severity.HIGH,
        description="Asks the model to pretend it has no safety restrictions",
    ),
    PatternRule(
        id="RM-003",
        category="role_manipulation",
        pattern=_p(r"\bact\s+as\s+if\s+you\s+(have\s+no|had\s+no)\s+(restrictions?|filters?|rules?)\b"),
        severity=Severity.HIGH,
        description="Asks the model to act as though restrictions don't apply",
    ),
    PatternRule(
        id="RM-004",
        category="role_manipulation",
        pattern=_p(r"\bdeveloper\s+mode\b"),
        severity=Severity.MEDIUM,
        description="References the common 'developer mode' jailbreak framing",
    ),
    PatternRule(
        id="RM-005",
        category="role_manipulation",
        pattern=_p(r"\byou\s+(have\s+been|are)\s+freed?\s+from\b"),
        severity=Severity.MEDIUM,
        description="Frames the model as having been 'freed' from its guidelines",
    ),
    PatternRule(
        id="RM-006",
        category="role_manipulation",
        pattern=_p(r"\bhypothetically,?\s+if\s+you\s+had\s+no\s+(restrictions?|rules?|filters?)\b"),
        severity=Severity.MEDIUM,
        description="Hypothetical framing used to sidestep restrictions",
    ),
    PatternRule(
        id="RM-007",
        category="role_manipulation",
        pattern=_p(r"\bfrom\s+now\s+on,?\s+you\s+(will|must|shall)\s+(act|behave|respond)\s+as\b"),
        severity=Severity.MEDIUM,
        description="Attempts a persistent role/behavior override",
    ),
]
