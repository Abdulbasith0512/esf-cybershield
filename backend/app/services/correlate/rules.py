"""Correlation rules: entity resolution, linking, scoring, severity, text.

Operates ONLY on DetectionResult public fields + metadata and (optionally)
an events_by_id map of top-level event columns. Never reads raw_event.
"""

from datetime import datetime, timedelta

from app.services.correlate.config import CorrelatorConfig
from app.services.correlate.fingerprint import incident_id_for
from app.services.correlate.models import Incident
from app.services.detect.common import coerce_ts
from app.services.detect.models import DetectionResult

RULE_SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
UNKNOWN = "unknown"


def _naive(dt) -> datetime:
    return coerce_ts(dt)


def resolve_entities(detections: list[DetectionResult],
                     events_by_id: dict | None = None):
    """Return {detection_id: (user|None, host|None)}.

    Prefers evidence-event columns via events_by_id; falls back to rule
    metadata (AUTH-001 user/anchor, AUTH-002/003 user, NET-002 host/user,
    DATA-001 user/host). Missing stays None (never matches); the "unknown"
    sentinel never matches either.
    """
    resolved = {}
    for d in detections:
        user = host = None
        meta = d.metadata or {}
        users, hosts = set(), set()
        if events_by_id:
            for eid in d.evidence_event_ids:
                ev = events_by_id.get(eid) or {}
                if ev.get("user"):
                    users.add(ev["user"])
                if ev.get("host"):
                    hosts.add(ev["host"])
            # Unanimous evidence wins. Empty (no info) falls back to metadata.
            # Ambiguous (2+ distinct) stays None — never matches.
            if len(users) == 1:
                user = next(iter(users))
            elif not users:
                user = meta.get("user") or None
                if user == UNKNOWN:
                    user = None
            if len(hosts) == 1:
                host = next(iter(hosts))
            elif not hosts:
                host = meta.get("host") or None
                if host == UNKNOWN:
                    host = None
                elif host is None and isinstance(meta.get("anchor"), str) \
                        and meta["anchor"].startswith("host:"):
                    host = meta["anchor"][5:] or None
        else:
            user = meta.get("user") or None
            if user == UNKNOWN:
                user = None
            host = meta.get("host") or None
            if host == UNKNOWN:
                host = None
            elif host is None and isinstance(meta.get("anchor"), str) \
                    and meta["anchor"].startswith("host:"):
                host = meta["anchor"][5:] or None
        resolved[d.detection_id] = (user, host)
    return resolved


def _span(det: DetectionResult):
    return _naive(det.first_seen), _naive(det.last_seen)


def linked(a: DetectionResult, b: DetectionResult, ent: dict,
           config: CorrelatorConfig) -> tuple[bool, dict]:
    """Strict link predicate. Returns (linked, signals dict)."""
    ua, ha = ent[a.detection_id]
    ub, hb = ent[b.detection_id]
    if not ua or not ub or ua != ub:
        return False, {}
    if not ha or not hb or ha != hb:
        return False, {}
    a0, a1 = _span(a)
    b0, b1 = _span(b)
    gap = max(0.0, (max(a0, b0) - min(a1, b1)).total_seconds() / 60.0)
    if gap > config.window_minutes:
        return False, {}
    shared = set(a.evidence_event_ids) & set(b.evidence_event_ids)
    pair = tuple(sorted((a.rule_id, b.rule_id)))
    sequenced = pair in {tuple(sorted(p)) for p in config.sequence_pairs}
    if not shared and not sequenced:
        return False, {}
    return True, {"same_user": True, "same_host": True, "gap_minutes": round(gap, 2),
                  "shared_evidence": sorted(shared), "sequenced": sequenced,
                  "pair": [a.rule_id, b.rule_id]}


def score_group(members: list[DetectionResult], links: list[dict],
                config: CorrelatorConfig) -> float:
    """correlation_score in [0,1]. Formula: base entity+time weights plus the
    best link evidence observed in the group (shared evidence / sequence /
    multi-rule). All weights from CorrelatorConfig."""
    if len(members) == 1:
        d = members[0]
        base = 0.30 + 0.10 * RULE_SEVERITY_RANK.get(d.severity, 0) / 3.0
        return round(min(base + 0.10 * (d.confidence or 0), 1.0), 3)
    score = config.w_same_user + config.w_same_host + config.w_temporal
    if any(link.get("shared_evidence") for link in links):
        score += config.w_shared_evidence
    if any(link.get("sequenced") for link in links):
        score += config.w_sequence
    if len({d.rule_id for d in members}) > 1:
        score += config.w_multi_rule
    avg_conf = sum(d.confidence or 0 for d in members) / len(members)
    score = score + 0.10 * avg_conf
    return round(max(0.0, min(1.0, score)), 3)


def derive_severity(members: list[DetectionResult],
                    config: CorrelatorConfig) -> str:
    rules = {d.rule_id for d in members}
    if config.sev_critical_rules <= rules:
        return "CRITICAL"
    if config.full_chain_3 <= rules or (
            "AUTH-001" in rules and ("PROC-001" in rules or "PROC-002" in rules)):
        return "HIGH"
    if any(d.severity in ("HIGH", "CRITICAL") for d in members):
        return "HIGH"
    if any(d.severity == "MEDIUM" for d in members):
        return "MEDIUM"
    return "LOW"


_TITLES = [
    (frozenset({"AUTH-001", "PROC-001", "NET-001", "DATA-001"}),
     "Potential Credential Compromise with Suspicious Data Transfer"),
    (frozenset({"AUTH-001", "PROC-001", "NET-001"}),
     "Potential Credential Compromise Sequence"),
    (frozenset({"AUTH-001", "PROC-001"}), "Potential Credential Compromise Sequence"),
    (frozenset({"AUTH-001", "PROC-002"}), "Potential Credential Compromise Sequence"),
    (frozenset({"PROC-001", "NET-001"}), "Correlated Suspicious Process and Network Activity"),
    (frozenset({"NET-001", "DATA-001"}), "Suspicious External Activity with Data Transfer"),
]


def build_title(members: list[DetectionResult]) -> str:
    rules = {d.rule_id for d in members}
    for needed, title in _TITLES:
        if needed <= rules:
            return title
    if len(members) == 1:
        d = members[0]
        return f"{d.rule_name} — Single-Signal Observation"
    kinds = sorted({d.rule_id.split('-')[0] for d in members})
    return f"Correlated Suspicious Activity ({', '.join(kinds)})"


def build_reason(members: list[DetectionResult], user: str | None,
                 host: str | None, score: float) -> str:
    names = sorted({d.rule_name for d in members})
    rule_ids = sorted({d.rule_id for d in members})
    where = ""
    if user and host:
        where = f" for user '{user}' on host '{host}'"
    elif user:
        where = f" for user '{user}'"
    return (
        f"Correlated {len(members)} detections ({', '.join(rule_ids)}){where} "
        f"within the correlation window: {'; '.join(names)}. "
        f"Correlation score {score:.2f}. This is a potential multi-stage "
        f"security story assembled from individual signals — not a confirmed "
        f"compromise or breach.")


def build_incident(members: list[DetectionResult], user: str | None,
                   host: str | None, links: list[dict],
                   config: CorrelatorConfig) -> Incident:
    members = sorted(members, key=lambda d: d.fingerprint)
    det_ids = sorted(d.detection_id for d in members)
    ev_ids = sorted({eid for d in members for eid in d.evidence_event_ids})
    first = min(_naive(d.first_seen) for d in members)
    last = max(_naive(d.last_seen) for d in members)
    score = score_group(members, links, config)
    return Incident(
        incident_id=incident_id_for(det_ids),
        title=build_title(members),
        severity=derive_severity(members, config),
        status="OPEN",
        confidence=score,
        reason=build_reason(members, user, host, score),
        detection_ids=det_ids,
        evidence_event_ids=ev_ids,
        first_seen=first, last_seen=last,
        metadata={"rule_ids": sorted({d.rule_id for d in members}),
                  "user": user, "host": host,
                  "correlation_score": score,
                  "sequence_hits": sorted({tuple(sorted((a, b))) for link in links
                                           for a, b in [link.get("pair", ())] if a}),
                  "detection_count": len(members),
                  "event_count": len(ev_ids)},
    )
