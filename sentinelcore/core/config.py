from pydantic_settings import BaseSettings, SettingsConfigDict


from sentinelcore._version import __version__ as _PACKAGE_VERSION


class Settings(BaseSettings):
    app_name: str = "SentinelCore"
    # Read from sentinelcore._version, never duplicated. This was hardcoded
    # to "0.3.0" while the package was at 0.4.0, so the API advertised a
    # version the package had not been for two milestones -- a client
    # checking it got the wrong answer. test_packaging.py asserts the three
    # sources stay equal.
    version: str = _PACKAGE_VERSION
    environment: str = "development"
    upstream_base_url: str = "https://api.openai.com"
    upstream_timeout_seconds: float = 60.0
    audit_enabled: bool = True
    audit_db_path: str = "sentinelcore_audit.db"

    # Storage backend. Explicit, never inferred. SQLite stays the default so
    # the package works with no database to configure.
    storage_backend: str = "sqlite"
    postgres_url: str = ""          # never logged; redacted in health output
    postgres_pool_min: int = 1
    postgres_pool_max: int = 10

    # Retention. Audit data cannot grow forever; the row cap is a second,
    # independent bound because time alone cannot contain a burst inside the
    # window.
    retention_enabled: bool = True
    retention_audit_days: int = 30
    retention_feedback_days: int = 365
    retention_approvals_days: int = 90
    retention_max_audit_rows: int = 1_000_000
    retention_interval_seconds: int = 3600
    # Resource protection. OFF by default: a limiter tuned wrong causes an
    # outage, so the operator opts in. Limits are PER WORKER PROCESS --
    # divide by worker count. See sentinelcore/core/limits.py.
    rate_limit_enabled: bool = False
    rate_limit_requests: int = 120
    rate_limit_window_seconds: int = 60
    max_request_bytes: int = 1_000_000  # 1MB; scanning cost is linear in input length

    # Streaming hold-back. The proxy withholds this many characters of
    # already-scanned output before releasing them to the client.
    #
    # Without it, a secret split across a chunk boundary partially leaks:
    # measured, an AWS key streamed as "...AKIAIOSFOD" + "NN7EXAMPLE"
    # delivered the first 10 of its 20 characters before the completed
    # pattern was detected and the stream cut. The chunk that completes a
    # pattern was always suppressed correctly -- the problem is the chunks
    # already gone.
    #
    # The cost is latency: the client sees output roughly this many
    # characters behind the upstream. 96 covers AWS keys (20/40), SSNs,
    # credit cards, private-key headers and typical API keys with room to
    # spare. Longer patterns (JWTs, private key bodies) still leak a
    # bounded prefix -- set this higher to trade more latency for less
    # exposure, or 0 to restore the old immediate-release behaviour.
    stream_holdback_chars: int = 96

    # Escape hatch for enforce_auth_required(). Outside development, a
    # gateway with no API keys refuses to start: every role check is
    # skipped, which leaves the audit log and MCP baselines readable by
    # anyone who can open a socket, and the shipped container binds
    # 0.0.0.0. Running that way deliberately is legitimate -- behind a
    # service mesh that already authenticates, say -- but it has to be
    # said out loud, because the failure being prevented is nobody having
    # considered it.
    allow_unauthenticated: bool = False

    # Streaming re-scan window.
    #
    # The streaming proxy re-scanned the ENTIRE accumulated response on
    # every chunk. Cost is therefore O(N x chunks), and at realistic token
    # granularity that is ruinous -- measured on a 2,000-character
    # completion, same bytes to the client every time, only the chunk count
    # changing:
    #
    #       1 chunk    129 ms
    #     100 chunks   843 ms
    #     400 chunks  3257 ms   (~5 chars/chunk, i.e. roughly per-token)
    #
    # Three seconds of added latency on one streamed response is not a
    # tuning problem, it is a reason nobody deploys the gateway.
    #
    # Each chunk now scans only the last `stream_scan_window_chars` plus
    # the new content, with ONE full scan at end-of-stream as a backstop.
    # The tradeoff, stated precisely rather than buried: a pattern whose
    # length fits the window is still caught on the chunk that completes
    # it, before release. A pattern LONGER than the window is caught at the
    # final scan instead -- later, though the hold-back buffer means its
    # tail is still unreleased and the stream is still cut.
    #
    # 1024 against a longest measured rules match of 32 characters across
    # the 744-example corpus. 0 restores the full re-scan.
    stream_scan_window_chars: int = 256

    # How much NEW text must arrive before re-scanning. The window above
    # decides how much PRECEDING text comes with it.
    #
    # Re-scanning on every chunk is what makes the cost quadratic: work
    # grows with response length TIMES chunk count, and chunk count at
    # token granularity is large. Measured, characters handed to detectors
    # for one 8,000-character completion in 1,600 chunks:
    #
    #     re-scan every chunk, whole text    6,404,002   (~6.2 s of scanning)
    #     window 1024, every chunk           1,549,032   (~1.5 s)
    #     stride 64 + overlap 256               ~40,000   (~0.04 s)
    #
    # Narrowing the window alone was not enough -- 4x, still seconds --
    # because the per-chunk re-scan dominates. Scanning on accumulated
    # NEW text instead is what removes the chunk-count term.
    #
    # Must be <= stream_holdback_chars, so nothing is released before it
    # has been scanned. Asserted at startup rather than trusted.
    stream_scan_stride_chars: int = 64
    # Alerting. Off unless a sink is configured; the log sink costs nothing
    # and is the sensible default for a first deployment.
    alerts_log_enabled: bool = True
    alerts_webhook_url: str = ""
    alerts_slack_webhook_url: str = ""
    alerts_cooldown_seconds: float = 60.0
    approval_ttl_seconds: int = 3600  # unanswered approvals EXPIRE, and expiry is a refusal
    semantic_detector_enabled: bool = False  # optional LLM detector; SENDS TEXT TO A THIRD PARTY
    semantic_model: str = "gpt-4o-mini"
    # "verbalized" (model states a number) or "logprobs" (read P(yes) from
    # the token distribution). See Finding 8 in docs/research/README.md.
    semantic_confidence_mode: str = "verbalized"
    ml_detector_enabled: bool = False  # optional learned detector; see sentinelcore/detectors/ml_classifier/
    api_keys: str = ""  # "key1:role1,key2:role2,..." -- empty means auth disabled

    model_config = SettingsConfigDict(env_file=".env", env_prefix="SENTINELCORE_")


settings = Settings()
