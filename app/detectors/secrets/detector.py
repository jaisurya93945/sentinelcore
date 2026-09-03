"""Secret/credential detector. Same pattern as PIIDetector -- see its docstring."""

from app.detectors.base import BaseDetector
from app.detectors.registry import register_detector
from app.detectors.secrets.patterns import SECRET_PATTERNS, redact
from app.models.finding import Finding


@register_detector
class SecretDetector(BaseDetector):
    name = "secrets"

    def detect(self, text: str, context: dict | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for rule in SECRET_PATTERNS:
            match = rule.pattern.search(text)
            if match:
                findings.append(
                    Finding(
                        detector=self.name,
                        type=rule.category,
                        description=rule.description,
                        severity=rule.severity,
                        evidence={
                            "rule_id": rule.id,
                            "matched_text": redact(match.group(0)),
                            "span": [match.start(), match.end()],
                        },
                    )
                )
        return findings
