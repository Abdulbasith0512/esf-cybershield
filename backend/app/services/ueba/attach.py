"""Attach UEBA anomaly evidence to enriched incidents. Read-only wrt risk.

Pipeline: build observations ONCE over in-scope events (preserves causal IP
memory), score ONCE with the provided model, then per incident select
observations by entity match + observation_time <= last_seen + evidence
overlap. Never fits/refits, never reads ground truth, never mutates inputs,
never touches deterministic risk fields.
"""

import logging
from datetime import timedelta

from app.services.correlate.models import Incident
from app.services.detect.common import coerce_ts
from app.services.mitre.models import EnrichedIncident
from app.services.ueba.config import UebaConfig
from app.services.ueba.evidence import (
    IncidentWithUeba,
    UEBAIncidentEvidence,
    UebaObservationRef,
)
from app.services.ueba.features import build_observations
from app.services.ueba.model import UebaModel
from app.services.ueba.scoring import score_observations

logger = logging.getLogger("esf.ueba.attach")


def _window_end(start, config: UebaConfig):
    return start + timedelta(hours=config.window_hours)


def attach_ueba(enriched: list[EnrichedIncident], events_by_id: dict,
                model: UebaModel | None,
                config: UebaConfig | None = None) -> list[IncidentWithUeba]:
    """Attach behavioral evidence to each incident. Deterministic, sorted by
    incident fingerprint. `model=None` yields honest unavailable evidence."""
    config = config or (model.config if model is not None else UebaConfig())
    in_scope = [e for e in events_by_id.values() if isinstance(e, dict) and e.get("event_id")]
    observations: list[dict] = []
    scored: dict[tuple[str, str], object] = {}
    obs_by_key: dict[tuple[str, str], dict] = {}
    if model is not None and in_scope:
        observations = build_observations(in_scope, config)
        for result in score_observations(observations, model, config):
            scored[(result.entity_key, result.observation_time.isoformat())] = result
        obs_by_key = {(o["entity_key"], o["window_start"].isoformat()): o
                      for o in observations}
    out = []
    for item in sorted(enriched, key=lambda e: e.fingerprint):
        out.append(_attach_one(item, events_by_id, model, config, scored, obs_by_key))
    out.sort(key=lambda e: e.fingerprint)
    logger.info("ueba attach run: %d incidents", len(out))
    return out


def _attach_one(item: EnrichedIncident, events_by_id: dict, model: UebaModel | None,
                config: UebaConfig, scored: dict, obs_by_key: dict) -> IncidentWithUeba:
    inc: Incident = item.incident
    window_start, window_end = coerce_ts(inc.first_seen), coerce_ts(inc.last_seen)
    base_meta = {"model_expected": config.model_version,
                 "feature_version": config.feature_version}
    if model is None:
        return IncidentWithUeba(
            enriched=item,
            ueba=UEBAIncidentEvidence(
                incident_id=inc.incident_id, incident_fingerprint=inc.fingerprint,
                available=False, feature_window_start=window_start,
                feature_window_end=window_end,
                reason=("UEBA model unavailable: no behavioral anomaly evidence "
                        "attached. Deterministic risk is unaffected."),
                metadata=base_meta))
    user = (inc.metadata or {}).get("user")
    if not user:
        return IncidentWithUeba(
            enriched=item,
            ueba=UEBAIncidentEvidence(
                incident_id=inc.incident_id, incident_fingerprint=inc.fingerprint,
                available=False, feature_window_start=window_start,
                feature_window_end=window_end,
                reason=("UEBA unavailable: incident has no single attributed user, "
                        "so no behavioral baseline applies. Deterministic risk "
                        "is unaffected."),
                metadata=base_meta))
    refs: list[UebaObservationRef] = []
    for (entity, iso), result in scored.items():
        if entity != user:
            continue
        obs = obs_by_key.get((entity, iso))
        if obs is None or obs["window_start"] > window_end:
            continue  # no future leakage: windows after last_seen excluded
        overlap = sorted(set(obs["event_ids"]) & set(inc.evidence_event_ids))
        if not overlap:
            continue
        refs.append(UebaObservationRef(
            entity_key=entity, observation_time=obs["window_start"],
            anomaly_score=result.anomaly_score, anomaly_flag=result.anomaly_flag,
            baseline_status=result.metadata.get("baseline_status", "UNKNOWN"),
            feature_context=dict(result.metadata.get("feature_context", {})),
            event_overlap=overlap))
    refs.sort(key=lambda r: r.observation_time)
    if not refs:
        return IncidentWithUeba(
            enriched=item,
            ueba=UEBAIncidentEvidence(
                incident_id=inc.incident_id, incident_fingerprint=inc.fingerprint,
                available=False, feature_window_start=window_start,
                feature_window_end=window_end,
                reason=("UEBA found no behavioral observations overlapping this "
                        "incident's evidence within its time window. Deterministic "
                        "risk is unaffected."),
                metadata={**base_meta, "candidate_windows": 0}))
    flagged = [r for r in refs if r.anomaly_flag]
    top = max(refs, key=lambda r: r.anomaly_score)
    state = "behaviorally anomalous" if flagged else "not anomalous"
    return IncidentWithUeba(
        enriched=item,
        ueba=UEBAIncidentEvidence(
            incident_id=inc.incident_id, incident_fingerprint=inc.fingerprint,
            available=True, anomaly_score=top.anomaly_score,
            anomaly_flag=bool(flagged),
            model_version=model.config.model_version,
            feature_version=model.config.feature_version,
            feature_window_start=window_start, feature_window_end=window_end,
            observations=refs,
            reason=(f"UEBA behavioral anomaly evidence for user '{user}': "
                    f"{len(refs)} overlapping hourly observation(s), "
                    f"{len(flagged)} flagged anomalous, peak score "
                    f"{top.anomaly_score:.2f} at {top.observation_time.isoformat()}. "
                    f"Behavior is {state} relative to the learned baseline; "
                    f"this is analyst context, not proof of compromise."),
            metadata={**base_meta, "window_count": len(refs),
                      "flagged_count": len(flagged)}))
