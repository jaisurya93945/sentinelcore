# Observability

```
GET /metrics            # conventional scrape path
GET /api/v1/metrics     # same content, versioned path
```

Prometheus text exposition, format version 0.0.4.

## Why an endpoint and not just the dashboard

The dashboard is a user interface: somebody has to be looking at it. "Somebody has to be looking" is not an operational posture for the component sitting in front of every LLM call. Without a metrics feed a gateway can be watched but not **alerted on**, and the first question an SRE asks about a proxy is where `/metrics` is.

## What is exposed

| Metric | Type | Labels |
|---|---|---|
| `sentinelcore_scans_total` | counter | `endpoint`, `decision` |
| `sentinelcore_findings_total` | counter | `type`, `origin` |
| `sentinelcore_enforcement_total` | counter | `decision`, `status` |
| `sentinelcore_blocked_total` | counter | `stage` |
| `sentinelcore_scan_duration_seconds` | histogram | `endpoint` |
| `sentinelcore_uptime_seconds` | gauge | — |

`enforcement_total` carries **both** decision and enforcement status, because that pair is what distinguishes a decision from an action actually taken. Three separate defects in this codebase turned on exactly that distinction — a SANITIZE reported with nothing behind it — so it is worth being able to alert on directly:

```promql
# decisions claiming SANITIZE that enforced nothing
sum by (status) (sentinelcore_enforcement_total{decision="sanitize"})
```

## Two deliberate constraints

**No content, ever.** `/metrics` is mounted **without** a role dependency, alongside `/health`, because a scrape target that needs a credential is a scrape target that ends up unmonitored. The cost of that choice is that anyone who can reach the port can read these counters — so labels are finding *types*, decisions and outcomes, never scanned text and never evidence. An observer learns the shape of the traffic, which is the point, and nothing about what was in it. A test posts a known secret through `/api/v1/scan` and asserts it appears nowhere in the exposition; it fails if raw text reaches any label.

If the port is reachable by people who should not see traffic shape, put the scrape behind your own network boundary — the same thing you already do for most exporters.

**Bounded cardinality.** The classic way to take down a Prometheus server is a label whose values are unbounded, and a security gateway is full of tempting ones: tenant ids, tool names, paths. Every metric is capped at `MAX_SERIES_PER_METRIC` (200) and overflow folds into a single `__other__` value rather than being dropped, so a saturated metric still **totals correctly**. A dropped sample makes a counter quietly wrong, and a wrong counter is worse than a coarse one because it is still believed.

This project has made the unbounded-key mistake before — the rate limiter retained an entry per client, 50,000 clients meaning 50,000 entries — so the cap is here from the start rather than after an incident.

## No new dependency

`prometheus_client` is the obvious choice and would be a mandatory runtime dependency for a project whose core value is being small — three packages today, none heavy. The exposition format is documented, stable and line-oriented, so it is emitted directly. The tests assert the format rather than trusting that it looks right: bucket values must be monotonically non-decreasing, `+Inf` must equal the observation count, and label values must be escaped, since an unescaped quote or newline fails the entire scrape rather than one series.

## Recording never breaks a scan

`record_scan` swallows anything it cannot record. Metrics must never be the reason a security decision fails to be returned, and a test passes a deliberately hostile finding object through it to prove the endpoint still answers.

The registry is shared across request threads, so concurrent recording is tested rather than assumed — this project has already shipped one concurrency defect, a global mutated on `Guard()` construction, measured at 531 corrupted scans out of 800.

## Not provided

- OpenTelemetry traces or spans.
- Per-tenant metrics. Tenant is deliberately absent from labels: it is the highest-cardinality field available and the one most likely to be unbounded in a real deployment. Per-tenant analysis belongs in the audit store, which is queryable and access-controlled.
- Push gateway support; this is a scrape target.
