"""
Red-team transformations for evaluating SentinelCore against an adaptive
attacker.

SEPARATION: nothing in this package is imported by the enforcement path
(detectors, risk, policy, storage, gateway). A test asserts that, because a
benchmark that shares code with the system under test measures the code
rather than the system.
"""

from sentinelcore.redteam.transforms import (TRANSFORMS, AttackerTier, Preservation,
                                             TransformResult, apply, list_transforms)

__all__ = ["TRANSFORMS", "AttackerTier", "Preservation", "TransformResult",
           "apply", "list_transforms"]
