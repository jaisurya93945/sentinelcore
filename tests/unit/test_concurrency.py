"""
Concurrency and bounded-state regression tests.

Every test here corresponds to a defect that was present in shipped code
and was found by audit rather than by the existing suite -- which passed
throughout. Tests that pass are not evidence of correctness for properties
nobody asserted.
"""

import threading
import time

from sentinelcore import Guard
from sentinelcore.core.config import settings
from sentinelcore.core.context import detector_enabled, detector_selection
from sentinelcore.core.limits import FixedWindowLimiter
from sentinelcore.services.alerts import AlertManager
from sentinelcore.models.finding import Finding, Severity


# --- P0: Guard detector selection must not leak across threads ---

def test_concurrent_guards_do_not_corrupt_each_others_detector_selection():
    """Measured before the fix: 531 of 800 scans ran with the wrong detector
    configuration, and the global flag was left permanently wrong. FastAPI
    runs sync endpoints in a threadpool, so this is the ordinary shape."""
    wrong = []

    def worker(guard, expected):
        for _ in range(150):
            with guard._active():
                time.sleep(0.0002)
                if detector_enabled("ml_detector") != expected:
                    wrong.append(1)

    threads = [
        threading.Thread(target=worker, args=(Guard(policy="strict"), True)),
        threading.Thread(target=worker, args=(Guard(policy="monitor"), False)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not wrong, f"{len(wrong)} scans ran with the wrong detector configuration"


def test_guard_never_writes_global_settings():
    """The root cause. A library must not reconfigure its host process."""
    before = (settings.ml_detector_enabled, settings.semantic_detector_enabled)
    g = Guard(policy="strict")
    with g._active():
        pass
    g.scan("hello")
    assert (settings.ml_detector_enabled, settings.semantic_detector_enabled) == before


def test_detector_selection_scopes_nest_and_restore():
    with detector_selection(ml_detector=True):
        assert detector_enabled("ml_detector") is True
        with detector_selection(semantic_detector=True):
            assert detector_enabled("ml_detector") is True, "inner scope must not clear the outer one"
            assert detector_enabled("semantic_detector") is True
        assert detector_enabled("semantic_detector") is False
    assert detector_enabled("ml_detector") is False


def test_override_falls_back_to_global_settings_outside_any_scope(monkeypatch):
    """The gateway configures detectors process-wide; that path must still work."""
    monkeypatch.setattr(settings, "ml_detector_enabled", True)
    assert detector_enabled("ml_detector") is True


# --- P0: the rate limiter must bound its own state ---

def test_limiter_key_space_is_bounded():
    """Measured before the fix: 50,000 unique clients retained 50,000
    entries, unbounded -- a memory-exhaustion vector inside the component
    whose job is preventing resource exhaustion."""
    lim = FixedWindowLimiter(100, 60, max_clients=500)
    for i in range(5000):
        lim.check(f"ip:10.0.{i // 256}.{i % 256}")
    assert lim.tracked_clients <= 500
    assert lim.evictions > 0


def test_eviction_is_least_recently_used_not_oldest_inserted():
    """An attacker generating fresh identities should evict their own stale
    entries; a steady legitimate client should keep its slot."""
    lim = FixedWindowLimiter(100, 60, max_clients=3)
    for k in ("a", "b", "c"):
        lim.check(k)
    lim.check("a")   # 'a' becomes most recently used
    lim.check("d")   # forces one eviction
    assert "a" in lim._counts, "a recently active client was evicted"
    assert "b" not in lim._counts, "the least recently used client should have gone"


def test_limiter_is_thread_safe_under_contention():
    lim = FixedWindowLimiter(max_requests=500, window_seconds=60)
    allowed = []

    def worker():
        for _ in range(100):
            if lim.check("shared")[0]:
                allowed.append(1)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(allowed) == 500, f"expected exactly the budget to be granted, got {len(allowed)}"


# --- P1: alert counters must not lose increments ---

def test_alert_counters_survive_concurrent_dispatch():
    """`+=` on an int is load-add-store, not atomic. These counters are how
    an operator discovers a sink has been failing."""
    mgr = AlertManager(cooldown_seconds=0)
    mgr.register("sink", lambda a: None)
    f = [Finding(detector="d", type="instruction_override", description="x", severity=Severity.HIGH)]

    def worker():
        for i in range(50):
            mgr.notify(f"s{i}", "scan", "block", 60, f)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    mgr.flush()
    assert mgr.stats.dispatched == 300, f"lost counter increments: {mgr.stats.dispatched}/300"
    mgr.clear_sinks()


# --- P2: the dict policy form must actually apply ---

def test_dict_policy_overrides_are_applied_not_ignored():
    """Previously stored in an unused attribute, so Guard(policy={...})
    silently behaved as 'balanced' -- an API that accepts configuration and
    discards it."""
    g = Guard(policy={"tool_authorization": False})
    assert g.preset.tool_authorization is False
    assert g.check_tool_call("database.delete", {"table": "logs"}).allowed, (
        "tool authorization was disabled by the override but still enforced"
    )


def test_dict_policy_rejects_unknown_fields():
    import pytest

    with pytest.raises(ValueError):
        Guard(policy={"not_a_real_field": True})
