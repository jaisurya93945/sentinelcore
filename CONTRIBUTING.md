# Contributing to SentinelCore

## Adding a new detector

Every detector subclasses `BaseDetector` and self-registers with `@register_detector`. No core files need to change.

```python
from app.detectors.base import BaseDetector
from app.detectors.registry import register_detector
from app.models.finding import Finding, Severity


@register_detector
class MyDetector(BaseDetector):
    name = "my_detector"

    def detect(self, text: str, context: dict | None = None) -> list[Finding]:
        findings = []
        # your detection logic here
        return findings
```

Drop the module under `app/detectors/`, import it once so the registration decorator runs, and it's available to the gateway.

## Running tests

```bash
pip install -r requirements.txt
pytest --cov=app tests/ -v
```

## Ground rules

- No fabricated benchmark numbers, ever — see the Authenticity Policy in `README.md`.
- New detectors need unit tests before merge.
- Mark unproven or experimental detection logic explicitly as `experimental` in your PR description.
- If a detector fails against a known attack class, document the limitation — don't hide it.
