"""Deterministic rule-to-technique mapper. Reads rule_ids + detection metadata
only. Never touches raw_event, ground truth, DB, or network."""

from app.services.correlate.models import Incident
from app.services.detect.models import DetectionResult
from app.services.mitre.mapping import CATALOG_VERSION, RULE_TO_MITRE, TECHNIQUES
from app.services.mitre.models import MitreMapping


def _pattern_of(det: DetectionResult) -> str | None:
    return (det.metadata or {}).get("pattern_id")


def map_incident(incident: Incident,
                 detections_by_id: dict[str, DetectionResult]) -> list[MitreMapping]:
    """Map each member detection to techniques. Dedupes identical
    (technique, rule) pairs; preserves per-technique source provenance via
    one entry per (technique, source rule). Sorted by technique_id."""
    out: dict[tuple[str, str], MitreMapping] = {}
    for det_id in sorted(incident.detection_ids):
        det = detections_by_id.get(det_id)
        if det is None:
            continue
        for entry in RULE_TO_MITRE.get(det.rule_id, []):
            patterns = entry.get("patterns")
            if patterns and _pattern_of(det) not in patterns:
                continue
            tech = TECHNIQUES[entry["technique_id"]]
            key = (entry["technique_id"], det.rule_id)
            if key in out:
                continue
            conf = max(0.0, min(1.0, entry["confidence"]))
            out[key] = MitreMapping(
                technique_id=tech["technique_id"],
                technique_name=tech["name"],
                tactic=tech["tactic"],
                source_rule_id=det.rule_id,
                rationale=entry["rationale"],
                confidence=conf,
                catalog_version=CATALOG_VERSION,
            )
    return [out[k] for k in sorted(out)]
