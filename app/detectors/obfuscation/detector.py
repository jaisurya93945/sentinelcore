"""
Obfuscation detector.

Character/encoding-level checks (Phase 2 baseline): zero-width characters,
bidi control characters, unusual whitespace, mixed-script homoglyphs,
suspected encoded payloads, entity-encoding, and raw control characters.
Deterministic, no ML -- every finding traces back to exactly what was
found and where.
"""

from app.detectors.base import BaseDetector
from app.detectors.obfuscation.patterns import (
    BASE64_BLOB_RE,
    BIDI_CONTROL_CHARS,
    HTML_ENTITY_RE,
    UNUSUAL_SPACE_CHARS,
    ZERO_WIDTH_CHARS,
    find_control_characters,
    find_mixed_script_runs,
)
from app.detectors.registry import register_detector
from app.models.finding import Finding, Severity


@register_detector
class ObfuscationDetector(BaseDetector):
    name = "obfuscation"

    def detect(self, text: str, context: dict | None = None) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_char_table(text, ZERO_WIDTH_CHARS, "zero_width_characters", Severity.HIGH))
        findings.extend(self._check_char_table(text, BIDI_CONTROL_CHARS, "bidi_control_characters", Severity.HIGH))
        findings.extend(self._check_char_table(text, UNUSUAL_SPACE_CHARS, "unusual_whitespace", Severity.LOW))
        findings.extend(self._check_mixed_script(text))
        findings.extend(self._check_encoded_payload(text))
        findings.extend(self._check_html_entities(text))
        findings.extend(self._check_control_characters(text))
        return findings

    def _check_char_table(
        self, text: str, table: dict[str, str], finding_type: str, severity: Severity
    ) -> list[Finding]:
        hits = [(ch, i) for i, ch in enumerate(text) if ch in table]
        if not hits:
            return []
        names = sorted({table[ch] for ch, _ in hits})
        return [
            Finding(
                detector=self.name,
                type=finding_type,
                description=f"Found {len(hits)} occurrence(s) of: {', '.join(names)}",
                severity=severity,
                evidence={
                    "count": len(hits),
                    "characters": names,
                    "positions": [i for _, i in hits][:20],  # cap evidence size
                },
            )
        ]

    def _check_mixed_script(self, text: str) -> list[Finding]:
        runs = find_mixed_script_runs(text)
        return [
            Finding(
                detector=self.name,
                type="mixed_script_homoglyph",
                description=(
                    f"Word mixes scripts ({'/'.join(sorted(scripts))}), "
                    "a common homoglyph substitution signal"
                ),
                severity=Severity.MEDIUM,
                evidence={"word": word, "span": [start, end], "scripts": sorted(scripts)},
            )
            for word, start, end, scripts in runs
        ]

    def _check_encoded_payload(self, text: str) -> list[Finding]:
        return [
            Finding(
                detector=self.name,
                type="encoded_payload_suspected",
                description="Long base64-like sequence found -- may hide an encoded payload (not decoded/inspected in v0.1)",
                severity=Severity.LOW,
                evidence={"matched_text": m.group(0)[:60], "span": [m.start(), m.end()]},
            )
            for m in BASE64_BLOB_RE.finditer(text)
        ]

    def _check_html_entities(self, text: str) -> list[Finding]:
        matches = HTML_ENTITY_RE.findall(text)
        if len(matches) < 3:
            return []
        return [
            Finding(
                detector=self.name,
                type="entity_encoding_obfuscation",
                description=f"Found {len(matches)} HTML/numeric character entities -- possible obfuscation via entity encoding",
                severity=Severity.MEDIUM,
                evidence={"count": len(matches), "sample": matches[:10]},
            )
        ]

    def _check_control_characters(self, text: str) -> list[Finding]:
        hits = find_control_characters(text)
        if not hits:
            return []
        return [
            Finding(
                detector=self.name,
                type="control_characters",
                description=f"Found {len(hits)} raw control character(s) in input",
                severity=Severity.MEDIUM,
                evidence={
                    "count": len(hits),
                    "codepoints": sorted({f"U+{ord(ch):04X}" for ch, _ in hits}),
                },
            )
        ]
