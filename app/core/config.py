from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: str = "postgresql+asyncpg://user:password@db:5432/secuscan"
    jwt_secret_key: str = ""
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    rate_limit_per_hour: int = 10
    allowed_port_range_start: int = 1
    allowed_port_range_end: int = 1024
    environment: str = "development"

    # Bypass explícito para desarrollo local: permite escanear IPs privadas/loopback/link-local.
    # Ver app/core/target_guard.py. NUNCA debe quedar en true en un ambiente expuesto.
    allow_private_targets: bool = False

    port_scan_concurrency: int = 50
    port_scan_timeout_seconds: float = 1.0


@lru_cache
def get_settings() -> Settings:
    return Settings()
