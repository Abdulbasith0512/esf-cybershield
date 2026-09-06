"""Incident persistence. Stores already-generated incidents; recalculates nothing."""

from app.services.persist.incidents import upsert_incidents

__all__ = ["upsert_incidents"]
