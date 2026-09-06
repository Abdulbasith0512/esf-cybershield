"""Application configuration loaded from environment variables."""

from functools import lru_cache

from pydantic import PostgresDsn
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Backend settings. All values come from the environment / .env file."""

    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "esf-cybershield-backend"
    app_env: str = "development"
    backend_port: int = 8000
    database_url: PostgresDsn = (
        "postgresql+psycopg://esf:changeme@localhost:5432/esf"  # type: ignore[assignment]
    )
    cors_origins: list[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
    ]


@lru_cache
def get_settings() -> Settings:
    """Return cached settings instance."""
    return Settings()
