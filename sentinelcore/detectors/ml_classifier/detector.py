"""
Learned prompt-injection detector (optional, OFF by default).

TF-IDF (word 1-2 grams + character 3-5 grams) into a calibrated logistic
regression, trained by scripts/train_ml_detector.py. Held-out test
performance: P=93.65% R=85.51% F1=89.39% FPR=5.00% AUC=0.964 -- versus
the rules-based baseline's 17.68% recall at 0.50% FPR.

WHAT IT IS, PRECISELY
A LEARNED LEXICAL classifier. Not a transformer, not semantic
understanding. It generalises within the training vocabulary and inherits
that data's language bias (predominantly English). It will not understand
a genuinely novel semantic attack phrased in unseen terms. Calling it
"semantic" or "AI-powered detection" would be false advertising.

WHY IT IS OFF BY DEFAULT
Three real reasons, not caution theatre:
  1. It costs a 10x false-positive increase (0.50% -> 5.00%). That is the
     right trade for many deployments and the wrong one for others. The
     operator decides, not this file.
  2. Enabling it would make scikit-learn a mandatory runtime dependency
     for a project whose core value is being small and deterministic.
  3. Measured agent-level consequences are non-trivial: benign workflow
     completion drops from 93.3% to 80.0% (docs/research/README.md,
     Finding 5). That must be an opt-in.

Enable with SENTINELCORE_ML_DETECTOR_ENABLED=true, after installing
`pip install -r requirements-ml.txt` and training the model.

FAILURE BEHAVIOUR -- FAIL-OPEN, DELIBERATELY
If scikit-learn is absent, the model file is missing, or inference
raises, this detector logs once and returns no findings rather than
raising. That is fail-OPEN at the detector level and it is a real
security trade-off, stated rather than buried: a single optional
detector must not be able to take down a gateway on which every other
detector is still running correctly. The rules-based detectors, risk
engine, policy engine and tool authorization all continue to function.
The alternative -- failing the whole request -- converts a degraded
detection capability into a total outage, which is the worse failure for
a component that is optional by design.
"""

import logging
from pathlib import Path

from sentinelcore.core.config import settings
from sentinelcore.detectors.base import BaseDetector
from sentinelcore.detectors.registry import register_detector
from sentinelcore.models.finding import Finding, Severity

logger = logging.getLogger(__name__)

MODEL_PATH = Path(__file__).parent.parent.parent.parent / "dataset" / "processed" / "ml_detector.joblib"

# Probability -> severity. Derived from scripts/threshold_study.py: 10
# seeds, thresholds selected on VALIDATION only, evaluated on an untouched
# TEST split.
#
#   REPORTING_FLOOR 0.50 -- the max-F1 threshold averaged 0.46 across seeds
#       (range 0.25-0.64). 0.50 sits just above that mean, trading a little
#       recall for materially fewer false positives, which matters because
#       ambiguous findings are what provenance escalation converts into
#       hard blocks (docs/research/README.md, Finding 5).
#   HIGH_CONFIDENCE 0.80 -- the most STABLE low-FPR operating point found:
#       recall 72.0% [60.4-83.7], FPR 1.1% [0.0-2.5] across 10 seeds. It
#       beat adaptively selecting a per-seed zero-FPR threshold, which
#       swung 0.61-0.98 and still landed at 1.1% FPR on test.
#
# An earlier single-slice analysis suggested 0.79 achieved exactly 0% FPR.
# The multi-seed study did not reproduce that: no fixed threshold reliably
# reaches 0% FPR. These constants are set from the multi-seed result.
HIGH_CONFIDENCE = 0.80
REPORTING_FLOOR = 0.50


@register_detector
class MLClassifierDetector(BaseDetector):
    name = "ml_classifier"

    _model = None
    _load_failed = False

    @classmethod
    def _get_model(cls):
        if cls._model is not None or cls._load_failed:
            return cls._model
        try:
            import joblib

            cls._model = joblib.load(MODEL_PATH)
        except Exception as e:
            cls._load_failed = True
            logger.warning(
                f"ML detector enabled but unavailable ({e}). Continuing WITHOUT it -- "
                f"all rules-based detectors, risk scoring and policy enforcement are unaffected. "
                f"Install requirements-ml.txt and run scripts/train_ml_detector.py to enable."
            )
        return cls._model

    def detect(self, text: str, context: dict | None = None) -> list[Finding]:
        if not settings.ml_detector_enabled or not text.strip():
            return []

        model = self._get_model()
        if model is None:
            return []

        try:
            probability = float(model.predict_proba([text])[0][1])
        except Exception as e:
            logger.warning(f"ML detector inference failed, skipping this input: {e}")
            return []

        if probability < REPORTING_FLOOR:
            return []

        return [
            Finding(
                detector=self.name,
                type="ml_injection",
                description=f"Learned classifier flagged this content (p={probability:.2f})",
                severity=Severity.HIGH if probability >= HIGH_CONFIDENCE else Severity.MEDIUM,
                # The first legitimate use of this field in the project.
                # The Finding schema has always said confidence is "only set
                # if the underlying detector is calibrated" -- this model is
                # calibrated (CalibratedClassifierCV), so the number is real
                # rather than fabricated.
                confidence=round(probability, 4),
                evidence={"probability": round(probability, 4), "model": "tfidf+logreg"},
            )
        ]
