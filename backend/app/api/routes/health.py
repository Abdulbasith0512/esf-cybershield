"""Liveness probe endpoint."""

from fastapi import APIRouter
from pydantic import BaseModel


class HealthResponse(BaseModel):
    """Structured health payload."""

    status: str
    service: str


router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse, summary="Service health")
def get_health() -> HealthResponse:
    """Return service liveness without touching the database."""
    return HealthResponse(status="healthy", service="esf-cybershield-backend")
