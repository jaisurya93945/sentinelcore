from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "SentinelCore"
    version: str = "0.1.0"
    environment: str = "development"
    upstream_base_url: str = "https://api.openai.com"
    upstream_timeout_seconds: float = 60.0
    audit_enabled: bool = True
    audit_db_path: str = "sentinelcore_audit.db"

    model_config = SettingsConfigDict(env_file=".env", env_prefix="SENTINELCORE_")


settings = Settings()
