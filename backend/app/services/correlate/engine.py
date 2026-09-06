"""Correlation engine: dedupe, resolve, link (union-find), assemble. No scoring logic here."""

import logging

from app.services.correlate.config import CorrelatorConfig
from app.services.correlate.models import Incident
from app.services.correlate.rules import build_incident, linked, resolve_entities
from app.services.detect.common import coerce_ts
from app.services.detect.models import DetectionResult

logger = logging.getLogger("esf.correlate")


def correlate(detections: list[DetectionResult],
              events_by_id: dict | None = None,
              config: CorrelatorConfig | None = None) -> list[Incident]:
    """Group detections into incidents. Deterministic: identical input +
    config -> identical incidents sorted by fingerprint. Never modifies
    inputs, never touches the DB, never reads ground truth.
    """
    config = config or CorrelatorConfig()
    unique: dict[str, DetectionResult] = {}
    for d in detections:
        unique.setdefault(d.fingerprint, d)
    dets = sorted(unique.values(),
                  key=lambda d: (coerce_ts(d.first_seen), d.fingerprint))
    if not dets:
        return []
    ent = resolve_entities(dets, events_by_id)

    parent = {d.detection_id: d.detection_id for d in dets}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)

    links: dict[frozenset, dict] = {}
    for i in range(len(dets)):
        for j in range(i + 1, len(dets)):
            ok, signals = linked(dets[i], dets[j], ent, config)
            if ok:
                union(dets[i].detection_id, dets[j].detection_id)
                links.setdefault(frozenset((dets[i].detection_id,
                                            dets[j].detection_id)), signals)
    groups: dict[str, list[DetectionResult]] = {}
    for d in dets:
        groups.setdefault(find(d.detection_id), []).append(d)

    incidents = []
    for root in sorted(groups):
        members = groups[root]
        member_ids = {d.detection_id for d in members}
        group_links = [sig for pair, sig in links.items() if pair <= member_ids]
        users = {u for u, _ in (ent[d.detection_id] for d in members) if u}
        hosts = {h for _, h in (ent[d.detection_id] for d in members) if h}
        user = next(iter(users)) if len(users) == 1 else None
        host = next(iter(hosts)) if len(hosts) == 1 else None
        incidents.append(build_incident(members, user, host, group_links, config))
    incidents.sort(key=lambda inc: inc.fingerprint)
    logger.info("correlation run: %d detections -> %d incidents", len(dets), len(incidents))
    return incidents
