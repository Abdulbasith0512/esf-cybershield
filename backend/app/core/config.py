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
    # Threat-intel enrichment (Slice 40). Only "local-test" ships; unknown
    # names degrade enrichment to unavailable without breaking investigation.
    threat_intel_provider: str = "local-test"
    threat_intel_timeout_seconds: float = 5.0
    threat_intel_cache_ttl_seconds: int = 3600
    # SOC Analyst Copilot (Slice 42). "fake" is the offline deterministic
    # default; "ollama" joins the registry only when ollama_host is set.
    llm_provider: str = "fake"
    llm_model: str = ""
    llm_timeout_seconds: float = 30.0
    llm_max_output_tokens: int = 1024
    llm_temperature: float = 0.0
    llm_max_question_length: int = 2000
    ollama_host: str = ""
    ollama_model: str = "llama3.1"


@lru_cache
def get_settings() -> Settings:
    """Return cached settings instance."""
    return Settings()
