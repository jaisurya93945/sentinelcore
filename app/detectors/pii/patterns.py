"""
Pattern definitions for the PII detector.

Deterministic regex, v0.1 baseline -- same philosophy as the other
detectors. Matched text is ALWAYS redacted before it goes into a Finding:
a security tool whose own findings/logs leak the PII it found would be a
genuine anti-pattern, not just a limitation. See docs/threat-model/README.md.
"""

import re
from dataclasses import dataclass

from app.models.finding import Severity


@dataclass(frozen=True)
class PIIRule:
    id: str
    category: str
    pattern: re.Pattern
    severity: Severity
    description: str


def _p(text: str) -> re.Pattern:
    return re.compile(text, re.IGNORECASE)


def redact(text: str) -> str:
    """First 2 + last 2 characters visible, everything else masked.
    Intentionally conservative -- adjust for stricter compliance needs."""
    if len(text) <= 4:
        return "*" * len(text)
    return text[:2] + "*" * (len(text) - 4) + text[-2:]


PII_PATTERNS: list[PIIRule] = [
    PIIRule(
        id="PII-001",
        category="email_address",
        pattern=_p(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"),
        severity=Severity.LOW,
        description="Email address found",
    ),
    PIIRule(
        id="PII-002",
        category="phone_number",
        pattern=_p(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b"),
        severity=Severity.LOW,
        description="Phone number (US-format) found",
    ),
    PIIRule(
        id="PII-003",
        category="ssn",
        pattern=_p(r"\b\d{3}-\d{2}-\d{4}\b"),
        severity=Severity.HIGH,
        description="US Social Security Number-shaped pattern found",
    ),
    PIIRule(
        id="PII-004",
        category="credit_card",
        pattern=_p(r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2})[- ]?\d{4}[- ]?\d{4}[- ]?\d{1,4}\b"),
        severity=Severity.HIGH,
        description="Credit card-shaped number found (Visa/Mastercard/Amex prefix, no Luhn check)",
    ),
    PIIRule(
        id="PII-005",
        category="ip_address",
        pattern=_p(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        severity=Severity.LOW,
        description="IPv4 address found",
    ),
]
