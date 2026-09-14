"""
Per-call detector selection.

WHY THIS EXISTS
An earlier implementation gave each Guard its detector selection by
mutating the global settings object for the duration of a call and
restoring it afterwards. That is unsound under concurrency: the
save/restore pairs interleave, so two Guards with different presets
corrupt each other and the "restored" value can be permanently wrong.

Measured before this module existed: with a `strict` Guard and a
`monitor` Guard running concurrently, **531 of 800 scans observed the
wrong detector configuration**, and the global flag was left at the wrong
value after both threads finished. FastAPI runs sync endpoints in a
threadpool, so that is the ordinary deployment shape, not an exotic one.

A ContextVar is the correct primitive: it is isolated per thread AND per
asyncio task, so a Guard's selection cannot escape the call that set it,
and no lock is needed on the read path.
"""

from contextlib import contextmanager
from contextvars import ContextVar

from sentinelcore.core.config import settings

# None means "no override in scope" -- fall back to global settings, which
# is what the gateway and any direct detector use rely on.
_overrides: ContextVar[dict | None] = ContextVar("sentinelcore_detector_overrides", default=None)


def detector_enabled(name: str) -> bool:
    """Whether an optional detector should run in the current context.

    Checks the per-call override first, then the global setting. Detectors
    call this instead of reading settings directly so that one code path
    serves both the library (per-Guard selection) and the gateway (process
    configuration).
    """
    override = _overrides.get()
    if override is not None and name in override:
        return override[name]
    return bool(getattr(settings, f"{name}_enabled", False))


@contextmanager
def detector_selection(**enabled: bool):
    """Scope a detector selection to the current thread/task.

        with detector_selection(ml_detector=True, semantic_detector=False):
            ...

    Nested scopes merge with the enclosing one rather than replacing it,
    so an inner scope that names only one detector leaves the rest alone.
    """
    current = _overrides.get() or {}
    token = _overrides.set({**current, **enabled})
    try:
        yield
    finally:
        _overrides.reset(token)
