"""
Detector package. Importing this package registers every built-in detector
via its `@register_detector` decorator -- new detectors just need one import
line added here (see CONTRIBUTING.md).
"""

from sentinelcore.detectors import ml_classifier  # noqa: F401
from sentinelcore.detectors import obfuscation  # noqa: F401
from sentinelcore.detectors import pii  # noqa: F401
from sentinelcore.detectors import prompt_injection  # noqa: F401
from sentinelcore.detectors import secrets  # noqa: F401
from sentinelcore.detectors import semantic  # noqa: F401
from sentinelcore.detectors import tool_arguments  # noqa: F401
