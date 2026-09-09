"""
Prompt injection baseline detector.

Rules + heuristics only (Phase 2 baseline) -- no ML/semantic detection yet.
Deliberately simple and fully transparent: every finding traces back to
exactly one named pattern rule, so results are auditable.
"""

from sentinelcore.detectors.base import BaseDetector
from sentinelcore.detectors.prompt_injection.patterns import PATTERNS
from sentinelcore.detectors.registry import register_detector
from sentinelcore.models.finding import Finding


@register_detector
class PromptInjectionDetector(BaseDetector):
    name = "prompt_injection"

    def detect(self, text: str, context: dict | None = None) -> list[Finding]:
        findings: list[Finding] = []

        for rule in PATTERNS:
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
                            "matched_text": match.group(0),
                            "span": [match.start(), match.end()],
                        },
                    )
                )

        return findings
