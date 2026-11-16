from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "VulnPrior"
    app_version: str = "2.0.0"
    environment: str = "development"
    database_url: str = "sqlite:///./vulnprior.db"
    cors_origins: str = "*"

    # Risk bands
    risk_critical_threshold: float = 80.0
    risk_high_threshold: float = 60.0
    risk_medium_threshold: float = 35.0

    # Explainable scoring weights (max contribution of each factor)
    weight_cvss: float = 24.0
    weight_epss: float = 24.0
    weight_kev: float = 18.0
    weight_ransomware: float = 6.0
    weight_criticality: float = 16.0
    weight_exposure: float = 8.0
    weight_data: float = 5.0
    weight_production: float = 3.0
    weight_patch: float = 2.0
    weight_control: float = -12.0

    # Remediation SLAs (hours)
    sla_kev_exposed_hours: int = 24
    sla_critical_hours: int = 48
    sla_high_hours: int = 168
    sla_medium_hours: int = 720
    sla_low_hours: int = 2160

    # Risk acceptance guardrails
    acceptance_max_days: int = 180
    kev_acceptance_max_days: int = 30

    # Threat-intelligence feeds
    epss_api_url: str = "https://api.first.org/data/v1/epss"
    kev_feed_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    feed_timeout_seconds: float = 20.0

    # Security: "key:role,key2:role2" — empty means demo mode (everyone is admin)
    api_keys: str = ""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


settings = Settings()
