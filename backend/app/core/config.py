"""Application configuration loaded from environment variables."""

from functools import lru_cache

from pydantic import Field
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
    # str (not PostgresDsn) so local SQLite fallback works for dev/tests.
    # Production uses PostgreSQL; SQLite is only for offline verification.
    database_url: str = "postgresql+psycopg://esf:changeme@localhost:5432/esf"
    cors_origins: list[str] = Field(
        default=["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:5173"]
    )
    # Ingest protection. Empty = open (local dev); set = required via X-API-Key.
    ingest_api_key: str = ""
    max_batch_size: int = 500
    max_page_size: int = 500


@lru_cache
def get_settings() -> Settings:
    """Return cached settings instance."""
    return Settings()
