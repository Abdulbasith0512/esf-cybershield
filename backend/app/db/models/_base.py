"""Shared helpers for ORM models."""

import uuid
from datetime import datetime


def new_uuid() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    # Naive UTC for SQLite + PostgreSQL portability.
    # (SQLite returns naive datetimes; stripping avoids aware/naive comparison bugs.)
    return datetime.utcnow()
