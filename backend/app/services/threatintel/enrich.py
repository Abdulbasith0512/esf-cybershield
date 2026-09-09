"""Incident enrichment workflow: IOC extraction -> provider -> context.

Read-only with respect to security events, detections, correlation, incident
detection/evidence, risk, UEBA, and MITRE. Inputs are never mutated; outputs
are fresh objects. Provider failure degrades one observable to unavailable —
it never raises, never 500s, never loses incident data.
"""

from datetime import datetime, timezone

from app.services.threatintel.cache import ThreatIntelCache
from app.services.threatintel.models import EnrichedObservable, Observable
from app.services.threatintel.observables import extract_observables
from app.services.threatintel.providers import ThreatIntelProvider


def _detection_link(detections: list, event_ids: set[str]) -> list[str]:
    linked = []
    for det in detections:
        evidence = set(getattr(det, "evidence_event_ids", None) or [])
        if evidence & event_ids:
            linked.append(det.detection_id)
    return sorted(set(linked))


def enrich_incident(incident_id: str, event_rows: list, detections: list,
                    provider: ThreatIntelProvider,
                    cache: ThreatIntelCache | None = None,
                    now: datetime | None = None) -> list[EnrichedObservable]:
    """Enrich every observable extracted from the incident's sampled events."""
    moment = now or datetime.now(timezone.utc)
    observables: list[Observable] = extract_observables(event_rows)
    enriched: list[EnrichedObservable] = []
    for observable in observables:
        cached = cache.get(provider.name, observable.type,
                           observable.normalized_value) if cache else None
        if cached is not None:
            result = cached
            available, error = True, None
        else:
            try:
                result = provider.lookup(observable)
            except Exception as exc:  # provider failure -> unavailable
                enriched.append(EnrichedObservable(
                    observable=observable, available=False, intelligence=None,
                    error=f"{provider.name} lookup failed: {type(exc).__name__}",
                    detection_ids=_detection_link(
                        detections, set(observable.event_ids)),
                    incident_id=incident_id,
                ))
                continue
            available, error = True, None
            if result.retrieved_at is None:
                result = result.model_copy(update={"retrieved_at": moment})
            if cache is not None:
                cache.put(result)
        enriched.append(EnrichedObservable(
            observable=observable, available=available, intelligence=result,
            error=error,
            detection_ids=_detection_link(detections, set(observable.event_ids)),
            incident_id=incident_id,
        ))
    return enriched
