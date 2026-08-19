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

Drop the module under `app/detectors/`, then add one import line to `app/detectors/__init__.py` so the registration decorator actually runs (see how `prompt_injection` and `obfuscation` are wired in there — same pattern, one more line).

## Running tests

```bash
pip install -r requirements-dev.txt
pytest --cov=app tests/ -v
```

## Checking a detector change against real data

If your change affects detection behavior (new pattern, fixed pattern, new check), measure it, don't just claim it:

```bash
pip install -r requirements.txt -r scripts/requirements.txt
python scripts/replay_lab.py snapshot before   # on main, before your change
# ... make your change ...
python scripts/replay_lab.py snapshot after
python scripts/replay_lab.py compare before after
```

This shows exactly what got newly caught, and — just as important — flags any regression (something previously caught that's now missed) or new false positive. Include the comparison output in your PR description. See `docs/research/README.md` for a full worked example.

## Ground rules

- No fabricated benchmark numbers, ever — see the Authenticity Policy in `README.md`.
- New detectors need unit tests before merge.
- Mark unproven or experimental detection logic explicitly as `experimental` in your PR description.
- If a detector fails against a known attack class, document the limitation — don't hide it.
