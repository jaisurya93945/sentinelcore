"""Tool argument detector -- see patterns.py for the full design reasoning."""

from app.detectors.base import BaseDetector
from app.detectors.registry import register_detector
from app.detectors.tool_arguments.patterns import TOOL_ARGUMENT_PATTERNS
from app.models.finding import Finding


@register_detector
class ToolArgumentDetector(BaseDetector):
    name = "tool_arguments"

    def detect(self, text: str, context: dict | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for rule in TOOL_ARGUMENT_PATTERNS:
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
                            "matched_text": match.group(0)[:100],
                            "span": [match.start(), match.end()],
                        },
                    )
                )
        return findings
