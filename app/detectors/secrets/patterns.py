"""
Pattern definitions for the secret/credential detector.

Kept separate from PII: secrets have sharply different false-positive
characteristics (an AWS key ID is nearly unambiguous; an email address is
common and low-risk) and severities. Matched text is always redacted --
same reasoning as pii/patterns.py.
"""

import re
from dataclasses import dataclass

from app.detectors.pii.patterns import redact  # shared redaction helper
from app.models.finding import Severity

__all__ = ["SecretRule", "SECRET_PATTERNS", "redact"]


@dataclass(frozen=True)
class SecretRule:
    id: str
    category: str
    pattern: re.Pattern
    severity: Severity
    description: str


def _p(text: str) -> re.Pattern:
    return re.compile(text, re.IGNORECASE)


SECRET_PATTERNS: list[SecretRule] = [
    SecretRule(
        id="SEC-001",
        category="aws_access_key",
        pattern=_p(r"\bAKIA[0-9A-Z]{16}\b"),
        severity=Severity.CRITICAL,
        description="AWS Access Key ID found",
    ),
    SecretRule(
        id="SEC-002",
        category="private_key",
        pattern=_p(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        severity=Severity.CRITICAL,
        description="Private key block found",
    ),
    SecretRule(
        id="SEC-003",
        category="generic_api_key",
        pattern=_p(
            r"(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)"
            r"['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}['\"]?"
        ),
        severity=Severity.HIGH,
        description="API key/secret-looking assignment found",
    ),
    SecretRule(
        id="SEC-004",
        category="jwt_token",
        pattern=_p(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        severity=Severity.MEDIUM,
        description="JWT-shaped token found",
    ),
    SecretRule(
        id="SEC-005",
        category="bearer_token",
        pattern=_p(r"\bBearer\s+[A-Za-z0-9_\-\.]{20,}\b"),
        severity=Severity.MEDIUM,
        description="Bearer token found",
    ),
    SecretRule(
        id="SEC-006",
        category="db_connection_string",
        pattern=_p(r"\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?)://[^\s:]+:[^\s@]+@[^\s/]+"),
        severity=Severity.HIGH,
        description="Database connection string with embedded credentials found",
    ),
]
