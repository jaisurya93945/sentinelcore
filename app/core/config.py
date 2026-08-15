from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "SentinelCore"
    version: str = "0.1.0"
    environment: str = "development"

    model_config = SettingsConfigDict(env_file=".env", env_prefix="SENTINELCORE_")


settings = Settings()
