"""
Detector package. Importing this package registers every built-in detector
via its `@register_detector` decorator -- new detectors just need one import
line added here (see CONTRIBUTING.md).
"""

from app.detectors import prompt_injection  # noqa: F401
