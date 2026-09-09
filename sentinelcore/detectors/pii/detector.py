"""
PII detector.

Rules-based, v0.1 baseline. Applies to any text passed to it -- the same
detector runs on input, RAG context, and (new) output; only the caller
decides where to point it. See sentinelcore/api/v1/scan.py and proxy.py for the
output-scanning wiring.
"""

from sentinelcore.detectors.base import BaseDetector
from sentinelcore.detectors.pii.patterns import PII_PATTERNS, redact
from sentinelcore.detectors.registry import register_detector
from sentinelcore.models.finding import Finding


@register_detector
class PIIDetector(BaseDetector):
    name = "pii"

    def detect(self, text: str, context: dict | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for rule in PII_PATTERNS:
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
