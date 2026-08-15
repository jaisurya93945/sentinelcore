"""
Detector registry -- enables the plugin architecture.

A detector registers itself with `@register_detector` and becomes
discoverable to the gateway without any change to core code.
"""

from app.detectors.base import BaseDetector

DETECTOR_REGISTRY: dict[str, type[BaseDetector]] = {}


def register_detector(cls: type[BaseDetector]) -> type[BaseDetector]:
    if not issubclass(cls, BaseDetector):
        raise TypeError(f"{cls.__name__} must subclass BaseDetector")
    if not getattr(cls, "name", None):
        raise ValueError(f"{cls.__name__} must define a class-level `name` attribute")
    DETECTOR_REGISTRY[cls.name] = cls
    return cls


def get_registered_detectors() -> dict[str, type[BaseDetector]]:
    return dict(DETECTOR_REGISTRY)
