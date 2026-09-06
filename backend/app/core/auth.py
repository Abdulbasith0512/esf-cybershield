"""API-key protection for ingestion endpoints.

Design: when INGEST_API_KEY is empty (local dev default) the dependency is a
no-op so reads/writes work without setup. When set, POST endpoints require a
matching X-API-Key header. GET endpoints stay open for local development but
accept the same dependency later without code changes.
"""

import logging
import secrets

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader

from app.core.config import get_settings

logger = logging.getLogger("esf.auth")
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_ingest_key(key: str | None = Security(_api_key_header)) -> None:
    """Enforce X-API-Key on writes when INGEST_API_KEY is configured."""
    expected = get_settings().ingest_api_key
    if not expected:
        return
    if key is None or not secrets.compare_digest(key, expected):
        logger.warning("ingest auth rejected")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing API key",
        )


def optional_auth() -> Depends:
    """Attach point so GET routes can adopt auth later with one-line change."""
    return Depends(require_ingest_key)
