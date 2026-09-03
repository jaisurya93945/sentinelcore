from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "SentinelCore"
    version: str = "0.3.0"
    environment: str = "development"
    upstream_base_url: str = "https://api.openai.com"
    upstream_timeout_seconds: float = 60.0
    audit_enabled: bool = True
    audit_db_path: str = "sentinelcore_audit.db"
    ml_detector_enabled: bool = False  # optional learned detector; see app/detectors/ml_classifier/
    api_keys: str = ""  # "key1:role1,key2:role2,..." -- empty means auth disabled

    model_config = SettingsConfigDict(env_file=".env", env_prefix="SENTINELCORE_")


settings = Settings()
