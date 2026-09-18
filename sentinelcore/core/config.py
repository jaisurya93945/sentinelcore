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
