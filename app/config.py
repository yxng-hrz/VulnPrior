from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "VulnPrior"
    environment: str = "development"
    database_url: str = "sqlite:///./vulnprior.db"
    cors_origins: str = "*"
    risk_critical_threshold: float = 80.0
    risk_high_threshold: float = 60.0
    risk_medium_threshold: float = 35.0

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
