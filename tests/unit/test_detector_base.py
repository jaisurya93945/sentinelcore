"""Unit tests for the detector plugin interface (app/detectors/base.py, registry.py)."""

import pytest

from app.detectors.base import BaseDetector
from app.detectors.registry import get_registered_detectors, register_detector
from app.models.finding import Finding, Severity


def test_cannot_instantiate_base_detector_directly():
    with pytest.raises(TypeError):
        BaseDetector()


def test_register_detector_requires_name():
    with pytest.raises(ValueError):

        @register_detector
        class NoNameDetector(BaseDetector):
            def detect(self, text: str, context: dict | None = None) -> list[Finding]:
                return []


def test_register_and_run_dummy_detector():
    @register_detector
    class DummyDetector(BaseDetector):
        name = "dummy_test_detector"

        def detect(self, text: str, context: dict | None = None) -> list[Finding]:
            if "trigger" in text:
                return [
                    Finding(
                        detector=self.name,
                        type="dummy_finding",
                        description="Trigger word found",
                        severity=Severity.LOW,
                    )
                ]
            return []

    assert "dummy_test_detector" in get_registered_detectors()

    detector = DummyDetector()
    assert detector.detect("hello world") == []

    findings = detector.detect("this text has a trigger word")
    assert len(findings) == 1
    assert findings[0].type == "dummy_finding"
    assert findings[0].severity == Severity.LOW
    assert findings[0].detector == "dummy_test_detector"
