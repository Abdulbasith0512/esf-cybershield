"""Threat-intelligence / IOC enrichment. Read-only, provider-agnostic, offline.

Slice 40 is architecture + local deterministic enrichment only. No external
provider, no API keys, no network access. Enrichment never alters detections,
incidents, risk, UEBA, or MITRE output — it only attaches contextual results.
"""

from app.services.threatintel.cache import ThreatIntelCache
from app.services.threatintel.enrich import enrich_incident
from app.services.threatintel.models import (
    EnrichedObservable,
    Observable,
    ThreatIntelResult,
)
from app.services.threatintel.observables import extract_observables, normalize_observable
from app.services.threatintel.providers import (
    LocalThreatIntelProvider,
    ThreatIntelError,
    ThreatIntelProvider,
    provider_registry,
)

__all__ = [
    "EnrichedObservable",
    "LocalThreatIntelProvider",
    "Observable",
    "ThreatIntelCache",
    "ThreatIntelError",
    "ThreatIntelProvider",
    "ThreatIntelResult",
    "enrich_incident",
    "extract_observables",
    "normalize_observable",
    "provider_registry",
]
