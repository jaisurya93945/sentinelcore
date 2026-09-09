from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "SentinelCore"
    version: str = "0.3.0"
    environment: str = "development"
    upstream_base_url: str = "https://api.openai.com"
    upstream_timeout_seconds: float = 60.0
    audit_enabled: bool = True
    audit_db_path: str = "sentinelcore_audit.db"
    # Resource protection. OFF by default: a limiter tuned wrong causes an
    # outage, so the operator opts in. Limits are PER WORKER PROCESS --
    # divide by worker count. See sentinelcore/core/limits.py.
    rate_limit_enabled: bool = False
    rate_limit_requests: int = 120
    rate_limit_window_seconds: int = 60
    max_request_bytes: int = 1_000_000  # 1MB; scanning cost is linear in input length
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
