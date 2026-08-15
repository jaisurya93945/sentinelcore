"""
Abstract detector interface.

Every SentinelCore detector -- built-in or third-party -- implements this
interface. This is what makes detectors pluggable: the gateway core never
needs to change when a new detector is added. See CONTRIBUTING.md.
"""

from abc import ABC, abstractmethod

from app.models.finding import Finding


class BaseDetector(ABC):
    """Base class all detectors must subclass."""

    name: str  # required: unique detector id, e.g. "prompt_injection"

    @abstractmethod
    def detect(self, text: str, context: dict | None = None) -> list[Finding]:
        """
        Analyze `text` (and optional `context`, e.g. conversation history or
        retrieved documents) and return a list of Finding objects.

        Must return an empty list -- never None -- when nothing is detected.
        """
        raise NotImplementedError
