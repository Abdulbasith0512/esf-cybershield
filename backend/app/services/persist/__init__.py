"""Persistence. Stores already-generated analysis; recalculates nothing."""

from app.services.persist.detections import upsert_detections
from app.services.persist.incidents import upsert_incidents

__all__ = ["upsert_detections", "upsert_incidents"]
