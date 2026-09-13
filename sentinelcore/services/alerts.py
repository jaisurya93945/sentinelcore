"""
Alerting on security decisions.

WHY THIS EXISTS
The audit trail has been complete since early on, and nothing watched it.
That made "continuous monitoring" a dashboard someone has to remember to
open, which is not monitoring.

THE CONSTRAINT THAT SHAPES EVERY DECISION HERE
An alert path that can hang, crash, or slow the gateway is worse than no
alert path. A webhook endpoint that goes down must not take the security
control plane with it. So:

  - dispatch is FIRE-AND-FORGET on a background thread; the request path
    never waits on a network call to a third party,
  - every sink failure is caught and logged, never raised,
  - a bounded queue DROPS the oldest alerts under pressure rather than
    growing without limit, and counts the drops,
  - a per-rule cooldown prevents one pathological client from generating
    thousands of notifications.

WHAT IS DELIBERATELY NOT HERE
No retry queue, no delivery guarantee, no persistence of undelivered
alerts. Alerts are a notification channel, not an audit record -- the
audit log is the record, and it is written synchronously and durably.
Conflating the two would mean a missed webhook looked like a missing
security event, which is the more dangerous failure.

REDACTION
Alerts carry finding TYPES, severities, origins, decision and risk score.
They never carry raw scanned text or finding evidence, for the same reason
the audit log does not: a notification channel routed to Slack or email is
one of the least controlled places a secret could end up.
"""

import logging
import queue
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from sentinelcore.models.finding import Decision, Finding

logger = logging.getLogger(__name__)

# Decisions worth waking someone for. WARN is excluded on purpose: it
# stops nothing, and alerting on it trains operators to ignore alerts.
DEFAULT_TRIGGERS = frozenset({Decision.BLOCK, Decision.HUMAN_APPROVAL})

MAX_QUEUE = 1000
DEFAULT_COOLDOWN_SECONDS = 60.0


@dataclass
class Alert:
    timestamp: str
    scan_id: str
    endpoint: str
    decision: str
    risk_score: int
    finding_types: list[str]
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp, "scan_id": self.scan_id, "endpoint": self.endpoint,
            "decision": self.decision, "risk_score": self.risk_score,
            "finding_types": self.finding_types, "detail": self.detail,
            "source": "sentinelcore",
        }

    def text(self) -> str:
        types = ", ".join(self.finding_types) or "no content findings"
        tail = f" [{self.detail}]" if self.detail else ""
        return (f"SentinelCore {self.decision.upper()} on {self.endpoint}{tail} "
                f"(risk {self.risk_score}): {types}")


@dataclass
class AlertStats:
    dispatched: int = 0
    delivered: int = 0
    failed: int = 0
    dropped_queue_full: int = 0
    suppressed_cooldown: int = 0


class AlertManager:
    """Fan-out to registered sinks on a background worker."""

    def __init__(self, triggers: frozenset = DEFAULT_TRIGGERS,
                 cooldown_seconds: float = DEFAULT_COOLDOWN_SECONDS):
        self.triggers = triggers
        self.cooldown_seconds = cooldown_seconds
        self.stats = AlertStats()
        self._sinks: list[tuple[str, Callable[[Alert], None]]] = []
        self._queue: queue.Queue = queue.Queue(maxsize=MAX_QUEUE)
        self._last_sent: dict[str, float] = {}
        self._lock = threading.Lock()
        self._worker: threading.Thread | None = None
        self._stop = threading.Event()

    # ------------------------------------------------------------- sinks

    def register(self, name: str, sink: Callable[[Alert], None]) -> None:
        with self._lock:
            self._sinks.append((name, sink))

    def clear_sinks(self) -> None:
        with self._lock:
            self._sinks.clear()

    @property
    def sink_names(self) -> list[str]:
        return [n for n, _ in self._sinks]

    # ---------------------------------------------------------- dispatch

    def _cooldown_key(self, alert: Alert) -> str:
        """Rate-limit per (endpoint, decision, finding shape) rather than
        per event, so a client looping one attack produces one alert
        instead of thousands -- while a genuinely new attack shape still
        gets through immediately."""
        return f"{alert.endpoint}|{alert.decision}|{','.join(sorted(alert.finding_types))}"

    def notify(self, scan_id: str, endpoint: str, decision: str, risk_score: int,
               findings: list[Finding], detail: str | None = None) -> bool:
        """Called from the request path. Returns whether the alert was
        queued. NEVER raises and never blocks on a network call."""
        try:
            if not self._sinks:
                return False
            try:
                if Decision(decision) not in self.triggers:
                    return False
            except ValueError:
                return False

            alert = Alert(
                timestamp=datetime.now(timezone.utc).isoformat(),
                scan_id=scan_id, endpoint=endpoint, decision=decision,
                risk_score=risk_score,
                finding_types=sorted({f.type for f in findings}),
                detail=detail,
            )

            key = self._cooldown_key(alert)
            now = time.monotonic()
            with self._lock:
                last = self._last_sent.get(key)
                if last is not None and (now - last) < self.cooldown_seconds:
                    self.stats.suppressed_cooldown += 1
                    return False
                self._last_sent[key] = now

            try:
                self._queue.put_nowait(alert)
            except queue.Full:
                # Drop rather than grow. An unbounded queue under attack is
                # a memory exhaustion vector in the component whose job is
                # to prevent resource exhaustion.
                self.stats.dropped_queue_full += 1
                return False

            self.stats.dispatched += 1
            self._ensure_worker()
            return True
        except Exception as e:  # pragma: no cover - defensive
            logger.warning(f"alert dispatch failed, request unaffected: {e}")
            return False

    def _ensure_worker(self) -> None:
        if self._worker is None or not self._worker.is_alive():
            self._stop.clear()
            self._worker = threading.Thread(target=self._run, name="sentinelcore-alerts", daemon=True)
            self._worker.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                alert = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            for name, sink in list(self._sinks):
                try:
                    sink(alert)
                    self.stats.delivered += 1
                except Exception as e:
                    self.stats.failed += 1
                    logger.warning(f"alert sink {name!r} failed: {e}")

    def flush(self, timeout: float = 2.0) -> None:
        """Drain the queue. For tests and graceful shutdown; not used on
        the request path."""
        self._ensure_worker()
        deadline = time.monotonic() + timeout
        while not self._queue.empty() and time.monotonic() < deadline:
            time.sleep(0.01)
        time.sleep(0.05)

    def reset_cooldown(self) -> None:
        with self._lock:
            self._last_sent.clear()


# ------------------------------------------------------------------ sinks

def webhook_sink(url: str, timeout: float = 5.0) -> Callable[[Alert], None]:
    """Generic JSON POST. Timeout is mandatory: a sink without one can hang
    the worker thread indefinitely."""
    def _send(alert: Alert) -> None:
        import httpx

        httpx.post(url, json=alert.to_dict(), timeout=timeout).raise_for_status()
    return _send


def slack_sink(webhook_url: str, timeout: float = 5.0) -> Callable[[Alert], None]:
    def _send(alert: Alert) -> None:
        import httpx

        httpx.post(webhook_url, json={"text": alert.text()}, timeout=timeout).raise_for_status()
    return _send


def logging_sink(level: int = logging.WARNING) -> Callable[[Alert], None]:
    """Always available, no dependencies, no network. The default worth
    enabling even when nothing else is configured."""
    def _send(alert: Alert) -> None:
        logger.log(level, alert.text())
    return _send


_manager = AlertManager()


def get_manager() -> AlertManager:
    return _manager
