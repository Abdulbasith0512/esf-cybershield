"""ORM model registry. Import all models so Alembic sees them."""

from app.db.models.incident import Incident, IncidentEvent, RiskEvent  # noqa: F401
from app.db.models.normalized_event import NormalizedEvent  # noqa: F401
from app.db.models.raw_event import RawEvent  # noqa: F401
from app.db.models.signals import Detection, MlScore, UebaScore  # noqa: F401
