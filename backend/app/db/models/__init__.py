"""ORM model registry. Import all models so Alembic sees them."""

from app.db.models.detection import Detection as DetectionRow  # noqa: F401
from app.db.models.incident import Incident as IncidentRow  # noqa: F401
from app.db.models.security_event import SecurityEvent  # noqa: F401
