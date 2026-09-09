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
FLOW_PREFIX = "FLOW-"


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


def _network_key(rule_id: str, meta: dict):
    """Deterministic network entity from detection metadata (label-free).

    Kinds: ("host", ip) for rate/byte/burst rules grouped by destination;
    ("service", ip, port|None) for brute-force keyed by destination service;
    ("scanner", ip) for port-scan sources; ("ppsvc", proto, port) for
    protocol/port novelty. None when no attributable entity exists (entropy
    fallback, GLOBAL/unknown keys, missing fields) — None never matches.
    """
    if rule_id == "FLOW-003":
        if meta.get("mode") == "global-fallback":
            return None
        sip = meta.get("source_ip")
        return ("scanner", sip) if sip else None
    if rule_id == "FLOW-005":
        proto, port = meta.get("protocol"), meta.get("destination_port")
        if not proto or port is None:
            return None
        return ("ppsvc", str(proto), str(port))
    if rule_id == "FLOW-002":
        ip, sep, port = (meta.get("key") or "").partition("|")
        if not sep or not ip or ip in ("GLOBAL", "?"):
            return None
        return ("service", ip, None if port in ("", "?") else port)
    if rule_id in ("FLOW-001", "FLOW-004", "FLOW-006"):
        key = meta.get("key")
        if not key or key in ("GLOBAL", "?"):
            return None
        return ("host", key)
    return None


def resolve_network(detections: list[DetectionResult]):
    """Map detection_id -> network entity key (or None). Metadata-only."""
    return {d.detection_id: _network_key(d.rule_id, d.metadata or {})
            for d in detections}


def _network_compatible(k1, k2) -> bool:
    """Entity agreement gate. Exact match, plus service-refines-host: a
    ("service", ip, port) detection addresses the ("host", ip) entity."""
    if k1 is None or k2 is None:
        return False
    if k1 == k2:
        return True
    if k1[0] == "host" and k2[0] == "service" and k1[1] == k2[1]:
        return True
    return k2[0] == "host" and k1[0] == "service" and k2[1] == k1[1]


def _flow_linked(a: DetectionResult, b: DetectionResult, config: CorrelatorConfig,
                 buckets, net) -> tuple[bool, dict]:
    """FLOW-to-FLOW network branch. Returns False for any non-FLOW pair, so
    existing user+host behavior is unreachable here and stays bit-identical."""
    if not (a.rule_id.startswith(FLOW_PREFIX) and b.rule_id.startswith(FLOW_PREFIX)):
        return False, {}
    ka = (net or {}).get(a.detection_id)
    if ka is None and net is None:
        ka = _network_key(a.rule_id, a.metadata or {})
    kb = (net or {}).get(b.detection_id)
    if kb is None and net is None:
        kb = _network_key(b.rule_id, b.metadata or {})
    if not _network_compatible(ka, kb):
        # Cross-entity pairs link only through a configured sequence pair
        # backed by shared bucket flows (e.g. scanner output feeding a
        # brute-force window); entity agreement alone is never bypassed
        # without overlap.
        pair = tuple(sorted((a.rule_id, b.rule_id)))
        sequenced = pair in {tuple(sorted(p)) for p in config.flow_sequence_pairs}
        if not sequenced:
            return False, {}
    else:
        pair = tuple(sorted((a.rule_id, b.rule_id)))
        sequenced = pair in {tuple(sorted(p)) for p in config.flow_sequence_pairs}
    a0, a1 = _span(a)
    b0, b1 = _span(b)
    gap = max(0.0, (max(a0, b0) - min(a1, b1)).total_seconds() / 60.0)
    if gap > config.network_window_minutes:
        return False, {}
    ba = (buckets or {}).get(a.detection_id)
    if ba is None:
        ba = frozenset(a.bucket_event_ids)
    bb = (buckets or {}).get(b.detection_id)
    if bb is None:
        bb = frozenset(b.bucket_event_ids)
    shared = sorted(ba & bb)
    if not shared and not (sequenced and _network_compatible(ka, kb)):
        return False, {}
    return True, {"network_entity": sorted([list(ka), list(kb)]),
                  "gap_minutes": round(gap, 2),
                  "shared_bucket": shared,
                  "shared_bucket_count": len(shared),
                  "sequenced": sequenced,
                  "pair": [a.rule_id, b.rule_id]}


def linked(a: DetectionResult, b: DetectionResult, ent: dict,
           config: CorrelatorConfig, buckets=None, net=None) -> tuple[bool, dict]:
    """Strict link predicate. Returns (linked, signals dict)."""
    ua, ha = ent[a.detection_id]
    ub, hb = ent[b.detection_id]
    if not ua or not ub or ua != ub:
        return _flow_linked(a, b, config, buckets, net)
    if not ha or not hb or ha != hb:
        return _flow_linked(a, b, config, buckets, net)
    a0, a1 = _span(a)
    b0, b1 = _span(b)
    gap = max(0.0, (max(a0, b0) - min(a1, b1)).total_seconds() / 60.0)
    if gap > config.window_minutes:
        return _flow_linked(a, b, config, buckets, net)
    shared = set(a.evidence_event_ids) & set(b.evidence_event_ids)
    pair = tuple(sorted((a.rule_id, b.rule_id)))
    sequenced = pair in {tuple(sorted(p)) for p in config.sequence_pairs}
    if not shared and not sequenced:
        return _flow_linked(a, b, config, buckets, net)
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
    if any(link.get("shared_bucket") for link in links):
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
    network_entities = [list(k) for k in sorted(
        {_network_key(d.rule_id, d.metadata or {}) for d in members
         if _network_key(d.rule_id, d.metadata or {}) is not None},
        key=repr)]
    return Incident(
        incident_id=incident_id_for(det_ids),
        title=build_title(members),
        severity=derive_severity(members, config),
        status="NEW",
        confidence=score,
        reason=build_reason(members, user, host, score),
        detection_ids=det_ids,
        evidence_event_ids=ev_ids,
        first_seen=first, last_seen=last,
        metadata={"rule_ids": sorted({d.rule_id for d in members}),
                  "user": user, "host": host,
                  "correlation_score": score,
                  "network_entities": network_entities,
                  "sequence_hits": sorted({tuple(sorted((a, b))) for link in links
                                           for a, b in [link.get("pair", ())] if a}),
                  "detection_count": len(members),
                  "event_count": len(ev_ids)},
    )
