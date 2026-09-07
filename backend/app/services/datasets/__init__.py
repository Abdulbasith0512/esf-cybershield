"""Public-dataset adapters: external telemetry -> canonical SecurityEvent dicts.

Adapters are normalization-only. They never touch PostgreSQL, never run
detection, and never use dataset labels as features. Labels survive solely
as evaluation-only metadata inside raw_event.
"""

from app.services.datasets.base import AdapterError, DatasetAdapter, RejectReason

__all__ = ["AdapterError", "DatasetAdapter", "RejectReason"]
