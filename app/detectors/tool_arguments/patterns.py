"""
Pattern definitions for the tool-argument detector.

Deterministic regex, same v0.1 philosophy as every other detector here.
This detector is registered like any other, so it runs on ordinary text
too (not just tool arguments) -- meaning a chat message that mentions
"DROP TABLE" or "rm -rf" as a genuine technical question will also
produce a low/medium-severity finding. That's a real, known
false-positive source, documented rather than hidden -- see
docs/threat-model/README.md.

Deliberately NOT given blanket category-level rules in policy.yaml
(unlike prompt_injection/pii/secrets): the severity gradient here is
doing real work (a bare ".." is a much weaker signal than "rm -rf /"),
so the risk-score threshold, not a category override, drives the
response. See docs/threat-model/README.md for the full reasoning.
"""

import re
from dataclasses import dataclass

from app.models.finding import Severity


@dataclass(frozen=True)
class ToolArgRule:
    id: str
    category: str
    pattern: re.Pattern
    severity: Severity
    description: str


def _p(text: str) -> re.Pattern:
    return re.compile(text, re.IGNORECASE)


TOOL_ARGUMENT_PATTERNS: list[ToolArgRule] = [
    # -- SQL injection-shaped patterns -----------------------------------
    ToolArgRule(
        id="TA-001",
        category="sql_injection_pattern",
        pattern=_p(r"\b(DROP|DELETE|TRUNCATE)\s+TABLE\b"),
        severity=Severity.HIGH,
        description="Destructive SQL statement found",
    ),
    ToolArgRule(
        id="TA-002",
        category="sql_injection_pattern",
        pattern=_p(r";\s*--"),
        severity=Severity.MEDIUM,
        description="SQL comment-based injection pattern found",
    ),
    ToolArgRule(
        id="TA-003",
        category="sql_injection_pattern",
        pattern=_p(r"\bOR\s+['\"]?1['\"]?\s*=\s*['\"]?1['\"]?"),
        severity=Severity.HIGH,
        description="Classic SQL tautology injection pattern found",
    ),
    # -- Shell injection-shaped patterns ----------------------------------
    ToolArgRule(
        id="TA-004",
        category="shell_injection_pattern",
        pattern=_p(r"rm\s+-rf\s+/"),
        severity=Severity.CRITICAL,
        description="Destructive shell command found",
    ),
    ToolArgRule(
        id="TA-005",
        category="shell_injection_pattern",
        pattern=_p(r"[;&|]\s*(cat|curl|wget|nc|bash|sh)\s"),
        severity=Severity.HIGH,
        description="Shell command-chaining pattern found",
    ),
    ToolArgRule(
        id="TA-006",
        category="shell_injection_pattern",
        pattern=_p(r"\$\([^)]+\)|`[^`]+`"),
        severity=Severity.HIGH,
        description="Shell command substitution pattern found",
    ),
    # -- Path traversal ----------------------------------------------------
    ToolArgRule(
        id="TA-007",
        category="path_traversal",
        pattern=_p(r"(?:\.\.[/\\]){2,}"),
        severity=Severity.MEDIUM,
        description="Path traversal pattern found",
    ),
    ToolArgRule(
        id="TA-008",
        category="path_traversal",
        pattern=_p(r"/etc/(passwd|shadow)\b"),
        severity=Severity.HIGH,
        description="Sensitive system file path found",
    ),
]
