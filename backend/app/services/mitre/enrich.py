"""Enrichment pipeline: Incident -> MITRE + risk -> EnrichedIncident.

Mapper and scorer are independent; enrich() only wires them. Deterministic,
order-invariant, never mutates inputs."""

import logging

from app.services.correlate.models import Incident
from app.services.detect.models import DetectionResult
from app.services.mitre.config import RiskConfig
from app.services.mitre.mapper import map_incident
from app.services.mitre.models import EnrichedIncident, RiskBand
from app.services.mitre.scorer import _band, score_risk

logger = logging.getLogger("esf.mitre")


def enrich(incidents: list[Incident],
           detections_by_id: dict[str, DetectionResult],
           config: RiskConfig | None = None) -> list[EnrichedIncident]:
    config = config or RiskConfig()
    out = []
    for inc in sorted(incidents, key=lambda i: i.fingerprint):
        mappings = map_incident(inc, detections_by_id)
        score, breakdown, explanation = score_risk(inc, detections_by_id, mappings, config)
        band: RiskBand = _band(score, config)
        out.append(EnrichedIncident(
            incident=inc, mitre_techniques=mappings, risk_score=score,
            risk_band=band, risk_breakdown=breakdown, risk_explanation=explanation))
    out.sort(key=lambda e: e.fingerprint)
    logger.info("enrichment run: %d incidents", len(out))
    return out
