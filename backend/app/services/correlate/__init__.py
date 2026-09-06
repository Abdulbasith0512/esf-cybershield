"""Deterministic detection correlation. Pure domain layer, no persistence."""

from app.services.correlate.engine import correlate
from app.services.correlate.models import Incident

__all__ = ["Incident", "correlate"]
