"""
Prometheus metrics, in-process and dependency-free.

WHY THIS EXISTS

A gateway with no metrics endpoint can be watched but not alerted on. The
dashboard is a user interface -- somebody has to be looking at it -- and
"somebody has to be looking" is not an operational posture for the
component sitting in front of every LLM call. The first question an SRE
asks about a proxy is where /metrics is.

WHY NOT prometheus_client

It is the obvious choice and it would be a mandatory runtime dependency
for a project whose stated core value is being small: three packages
today, none of them heavy. The Prometheus text exposition format is a
documented, stable, line-oriented format, and emitting it correctly is a
smaller problem than carrying a dependency into every install. The tests
assert the format rather than trusting that it looks right.

CARDINALITY IS BOUNDED, DELIBERATELY

The classic way to take down a Prometheus server is a label whose values
are unbounded -- a tenant id, a tool name, a path. Every series here is
capped (MAX_SERIES_PER_METRIC) and overflow is folded into a single
`__other__` label value rather than dropped silently, so a saturated
metric still totals correctly and says so. This project has made the
unbounded-key mistake before, in the rate limiter, where 50,000 clients
meant 50,000 retained entries; the cap is here from the start for the same
reason.

NOTHING HERE CARRIES CONTENT. Labels are finding TYPES, decisions and
outcomes -- never scanned text, never evidence, never a raw key. The audit
log holds metadata only for exactly this reason and metrics are a weaker
boundary than the audit log, not a stronger one: a scrape endpoint is
usually less protected than a database.
"""

import threading
import time
from collections import defaultdict

# One tenant per series, one finding type per series, and so on. Chosen to
# be generous for real deployments and still bounded.
MAX_SERIES_PER_METRIC = 200
OVERFLOW_LABEL = "__other__"

# Buckets in seconds. Scan latency was measured at 0.85 us/char, so a
# typical 2 KB prompt lands near 2 ms -- the lower buckets are where the
# resolution needs to be, and the upper ones exist to make a pathological
# input visible rather than merely "slow".
LATENCY_BUCKETS = (0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)


class _Registry:
    """Counters and histograms with a bounded number of label sets."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, dict[tuple, float]] = defaultdict(dict)
        self._hist_buckets: dict[str, dict[tuple, list[int]]] = defaultdict(dict)
        self._hist_sum: dict[str, dict[tuple, float]] = defaultdict(dict)
        self._hist_count: dict[str, dict[tuple, int]] = defaultdict(dict)
        self._started = time.time()

    def _key(self, store: dict, name: str, labels: tuple) -> tuple:
        """Folds into __other__ once a metric is at its series cap.

        Folding rather than dropping matters: a dropped sample makes a
        counter quietly wrong, and a wrong counter is worse than a coarse
        one because it is still believed.
        """
        existing = store[name]
        if labels in existing or len(existing) < MAX_SERIES_PER_METRIC:
            return labels
        return tuple((k, OVERFLOW_LABEL) for k, _ in labels)

    def inc(self, name: str, labels: dict | None = None, value: float = 1.0) -> None:
        lbl = tuple(sorted((labels or {}).items()))
        with self._lock:
            key = self._key(self._counters, name, lbl)
            self._counters[name][key] = self._counters[name].get(key, 0.0) + value

    def observe(self, name: str, seconds: float, labels: dict | None = None) -> None:
        lbl = tuple(sorted((labels or {}).items()))
        with self._lock:
            key = self._key(self._hist_count, name, lbl)
            if key not in self._hist_count[name]:
                self._hist_buckets[name][key] = [0] * len(LATENCY_BUCKETS)
                self._hist_sum[name][key] = 0.0
                self._hist_count[name][key] = 0
            for i, edge in enumerate(LATENCY_BUCKETS):
                if seconds <= edge:
                    self._hist_buckets[name][key][i] += 1
            self._hist_sum[name][key] += seconds
            self._hist_count[name][key] += 1

    def reset(self) -> None:
        """Tests only. Process metrics are monotonic by design."""
        with self._lock:
            self._counters.clear()
            self._hist_buckets.clear()
            self._hist_sum.clear()
            self._hist_count.clear()

    # --- exposition ------------------------------------------------------

    @staticmethod
    def _escape(value: str) -> str:
        """Per the exposition format: backslash, double quote, newline."""
        return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")

    def _fmt_labels(self, labels: tuple, extra: tuple = ()) -> str:
        items = list(labels) + list(extra)
        if not items:
            return ""
        return "{" + ",".join(f'{k}="{self._escape(v)}"' for k, v in items) + "}"

    def render(self) -> str:
        lines: list[str] = []
        with self._lock:
            for name in sorted(self._counters):
                meta = _METRIC_HELP.get(name, "")
                lines.append(f"# HELP {name} {meta}")
                lines.append(f"# TYPE {name} counter")
                for labels, value in sorted(self._counters[name].items()):
                    lines.append(f"{name}{self._fmt_labels(labels)} {value:g}")

            for name in sorted(self._hist_count):
                meta = _METRIC_HELP.get(name, "")
                lines.append(f"# HELP {name} {meta}")
                lines.append(f"# TYPE {name} histogram")
                for labels in sorted(self._hist_count[name]):
                    buckets = self._hist_buckets[name][labels]
                    for i, edge in enumerate(LATENCY_BUCKETS):
                        le = (("%g" % edge))
                        lines.append(
                            f"{name}_bucket{self._fmt_labels(labels, (('le', le),))} {buckets[i]}")
                    lines.append(
                        f"{name}_bucket{self._fmt_labels(labels, (('le', '+Inf'),))} "
                        f"{self._hist_count[name][labels]}")
                    lines.append(f"{name}_sum{self._fmt_labels(labels)} "
                                 f"{self._hist_sum[name][labels]:g}")
                    lines.append(f"{name}_count{self._fmt_labels(labels)} "
                                 f"{self._hist_count[name][labels]}")

        lines.append("# HELP sentinelcore_uptime_seconds Seconds since this process started.")
        lines.append("# TYPE sentinelcore_uptime_seconds gauge")
        lines.append(f"sentinelcore_uptime_seconds {time.time() - self._started:g}")
        return "\n".join(lines) + "\n"


_METRIC_HELP = {
    "sentinelcore_scans_total":
        "Scans completed, by endpoint and decision.",
    "sentinelcore_findings_total":
        "Findings produced, by detector finding type and origin. Types only, never content.",
    "sentinelcore_enforcement_total":
        "Enforcement outcomes, by decision and enforcement_status -- the pair that "
        "distinguishes a decision from an action actually taken.",
    "sentinelcore_scan_duration_seconds":
        "Scan wall time by endpoint.",
    "sentinelcore_blocked_total":
        "Requests or responses refused, by the stage that refused them.",
}

REGISTRY = _Registry()


def record_scan(endpoint: str, decision: str, duration_seconds: float | None = None,
                findings: list | None = None, enforcement_status: str | None = None,
                stage: str | None = None) -> None:
    """One call per completed scan, from the endpoints.

    Deliberately tolerant: metrics must never be the reason a security
    decision fails to be returned. Anything unexpected is counted as
    best-effort and dropped rather than raised.
    """
    try:
        REGISTRY.inc("sentinelcore_scans_total",
                     {"endpoint": endpoint, "decision": decision})
        if duration_seconds is not None:
            REGISTRY.observe("sentinelcore_scan_duration_seconds", duration_seconds,
                             {"endpoint": endpoint})
        for f in findings or []:
            ftype = getattr(f, "type", None) or "unknown"
            origin = getattr(f, "origin", None) or "input"
            REGISTRY.inc("sentinelcore_findings_total",
                         {"type": str(ftype), "origin": str(origin)})
        if enforcement_status:
            REGISTRY.inc("sentinelcore_enforcement_total",
                         {"decision": decision, "status": str(enforcement_status)})
        if decision == "block":
            REGISTRY.inc("sentinelcore_blocked_total", {"stage": stage or endpoint})
    except Exception:  # pragma: no cover - best effort by design
        pass


def render() -> str:
    return REGISTRY.render()
