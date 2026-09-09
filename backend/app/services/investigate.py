"""SOC investigation assembly. Read-only composition over persisted rows.

Builds a deterministic, analyst-facing investigation object from one stored
incident plus its stored detections and a bounded sample of its stored
events. Never reruns detectors, never fabricates missing fields: anything
unavailable is reported as unavailable.
"""

from datetime import datetime, timezone
from typing import Any

EVIDENCE_SAMPLE_LIMIT = 200

_UNAVAILABLE = "Not available"


def _aware(value):
    if isinstance(value, datetime) and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _iso(value) -> str:
    from app.services.detect.common import coerce_ts

    try:
        moment = coerce_ts(value)
    except (ValueError, TypeError):
        return str(value)
    if isinstance(moment, datetime):
        return moment.replace(tzinfo=timezone.utc).isoformat()
    return str(value)


def _event_dict(row) -> dict[str, Any]:
    return {
        "event_id": row.event_id,
        "timestamp": _aware(row.timestamp),
        "event_type": row.event_type,
        "source": row.source,
        "host": row.host,
        "user": row.user,
        "source_ip": row.source_ip,
        "destination_ip": row.destination_ip,
        "destination_port": row.destination_port,
        "protocol": row.protocol,
        "process_name": row.process_name,
        "command_line": row.command_line,
        "status": row.status,
    }


def _scrubbed_event(row) -> dict[str, Any]:
    data = _event_dict(row)
    raw = dict(getattr(row, "raw_event", None) or {})
    raw.pop("evaluation_only", None)
    data["raw_event"] = raw
    return data


def _entity_sets(dets: list, events: list[dict]) -> dict[str, list[str]]:
    hosts: set[str] = set()
    src_ips: set[str] = set()
    dst_ips: set[str] = set()
    ports: set[int] = set()
    protos: set[str] = set()
    users: set[str] = set()
    processes: set[str] = set()
    for event in events:
        for key, bucket in (("user", users), ("host", hosts),
                            ("source_ip", src_ips), ("destination_ip", dst_ips),
                            ("protocol", protos), ("process_name", processes)):
            value = event.get(key)
            if value:
                bucket.add(value)
        if event.get("destination_port") is not None:
            ports.add(event["destination_port"])
    return {
        "source_ips": sorted(src_ips),
        "destination_ips": sorted(dst_ips),
        "ports": sorted(ports),
        "protocols": sorted(protos),
        "users": sorted(users),
        "hosts": sorted(hosts),
        "processes": sorted(processes),
    }


def build_investigation(incident, detections: list, event_rows: list,
                        expected_detection_ids: list[str] | None = None) -> dict[str, Any]:
    """Assemble the investigation object. Inputs never mutated.

    event_rows are ORM SecurityEvent rows; they are projected to scrubbed
    dicts (evaluation_only removed) inside this function.
    """
    dets = sorted(detections, key=lambda d: (_iso(d.first_seen), d.detection_id))
    events = [_scrubbed_event(row) for row in event_rows]
    mitre = list(getattr(incident, "mitre_techniques", None) or [])
    by_rule: dict[str, list[str]] = {}
    for mapping in mitre:
        mid = mapping.get("technique_id") if isinstance(mapping, dict) else mapping.technique_id
        rule = mapping.get("source_rule_id") if isinstance(mapping, dict) else mapping.source_rule_id
        by_rule.setdefault(rule, []).append(mid)
    for rule in by_rule:
        by_rule[rule] = sorted(set(by_rule[rule]))

    timeline = []
    for det in dets:
        bucket = sorted(set(getattr(det, "bucket_event_ids", None) or []))
        timeline.append({
            "detection_id": det.detection_id,
            "rule_id": det.rule_id,
            "rule_name": det.rule_name,
            "severity": det.severity,
            "confidence": det.confidence,
            "first_seen": _aware(det.first_seen),
            "last_seen": _aware(det.last_seen),
            "evidence_count": len(det.evidence_event_ids or []),
            "bucket_count": len(bucket),
            "bucket_available": bool(bucket),
            "mitre_technique_ids": by_rule.get(det.rule_id, []),
        })

    entities = _entity_sets(dets, events)

    det_records = []
    for det in dets:
        bucket = sorted(set(getattr(det, "bucket_event_ids", None) or []))
        det_records.append({
            "detection_id": det.detection_id,
            "rule_id": det.rule_id,
            "rule_name": det.rule_name,
            "severity": det.severity,
            "confidence": det.confidence,
            "reason": det.reason,
            "fingerprint": f"{det.rule_id}:{','.join(sorted(det.evidence_event_ids or []))}",
            "first_seen": _aware(det.first_seen),
            "last_seen": _aware(det.last_seen),
            "evidence_event_ids": sorted(det.evidence_event_ids or []),
            "bucket_event_ids": bucket,
            "bucket_available": bool(bucket),
            "mitre_technique_ids": by_rule.get(det.rule_id, []),
        })

    meta = dict(getattr(incident, "incident_metadata", None) or {})
    user = meta.get("user")
    host = meta.get("host")
    rules = sorted({d.rule_id for d in dets})
    span = f"{_iso(dets[0].first_seen)} → {_iso(dets[-1].last_seen)}" if dets else _UNAVAILABLE
    where = ""
    if user and host:
        where = f" for user '{user}' on host '{host}'"
    elif user:
        where = f" for user '{user}'"
    elif host:
        where = f" on host '{host}'"
    summary_bits = [
        f"Incident '{incident.title}' ({incident.severity}) groups "
        f"{len(dets)} detection(s) ({', '.join(rules) if rules else 'no rules'}){where}.",
        f"Activity spans {span}.",
    ]
    breakdown = dict(getattr(incident, "risk_breakdown", None) or {})
    risk_factors = []
    factor_names = [
        ("severity_points", "incident severity"),
        ("diversity_points", "multiple distinct detection rules"),
        ("confidence_points", "mean detection confidence"),
        ("evidence_points", "evidence volume"),
        ("sequence_points", "recognized multi-stage sequence"),
        ("mitre_points", "ATT&CK technique mapping"),
        ("contextual_points", "threat-intel/process context"),
    ]
    for key, label in factor_names:
        points = breakdown.get(key, 0) or 0
        if points:
            risk_factors.append({"factor": label, "points": points})
    ueba = getattr(incident, "ueba_evidence", None) or {}
    ueba_available = bool(ueba.get("available", False)) if isinstance(ueba, dict) else bool(
        getattr(ueba, "available", False))
    if ueba_available:
        flag = ueba.get("anomaly_flag") if isinstance(ueba, dict) else getattr(ueba, "anomaly_flag", None)
        score = ueba.get("anomaly_score") if isinstance(ueba, dict) else getattr(ueba, "anomaly_score", None)
        ueba_context: Any = {"available": True, "anomaly_flag": flag, "anomaly_score": score,
                             "model_version": (ueba.get("model_version") if isinstance(ueba, dict)
                                               else getattr(ueba, "model_version", None))}
    else:
        ueba_context = {"available": False, "note": "No UEBA anomaly associated with this incident."}

    seq_hits = meta.get("sequence_hits") or []
    net_entities = meta.get("network_entities") or []
    correlation_bits = []
    if seq_hits:
        correlation_bits.append("recognized sequence " + ", ".join(
            "+".join(sorted(pair)) for pair in sorted({tuple(p) for p in seq_hits})))
    if net_entities:
        rendered = [":".join(str(part) for part in ent) for ent in net_entities]
        noun = "entities" if len(rendered) != 1 else "entity"
        correlation_bits.append(f"shared network {noun} {', '.join(rendered)}")
    if user or host:
        correlation_bits.append("shared entity" + (f" user '{user}'" if user else "")
                                + (" and" if user and host else "") + (f" host '{host}'" if host else ""))
    correlation_reason = ("Linked by " + "; ".join(correlation_bits) + "."
                          if correlation_bits else _UNAVAILABLE)

    mitre_context = [
        {"technique_id": (m.get("technique_id") if isinstance(m, dict) else m.technique_id),
         "technique_name": (m.get("technique_name") if isinstance(m, dict) else m.technique_name),
         "tactic": (m.get("tactic") if isinstance(m, dict) else m.tactic),
         "source_rule_id": (m.get("source_rule_id") if isinstance(m, dict) else m.source_rule_id),
         "rationale": (m.get("rationale") if isinstance(m, dict) else m.rationale),
         "confidence": (m.get("confidence") if isinstance(m, dict) else m.confidence),
         "catalog_version": (m.get("catalog_version") if isinstance(m, dict) else m.catalog_version)}
        for m in mitre
    ]

    unavailable = []
    found_ids = {d.detection_id for d in dets}
    missing = sorted(set(expected_detection_ids or []) - found_ids)
    if missing:
        unavailable.append("referenced detection(s) not stored: " + ", ".join(missing))
    if not dets:
        unavailable.append("detections")
    if not events:
        unavailable.append("evidence sample")
    if not mitre:
        unavailable.append("MITRE mappings")
    if not ueba_available:
        unavailable.append("UEBA evidence")
    if not user and not host:
        unavailable.append("user/host attribution")

    explanation = {
        "summary": " ".join(summary_bits),
        "trigger_detections": sorted(d.detection_id for d in dets),
        "correlation_reason": correlation_reason,
        "risk_factors": risk_factors,
        "mitre_context": [{"technique_id": m["technique_id"], "rule_ids": sorted(
            {mm.get("source_rule_id") if isinstance(mm, dict) else mm.source_rule_id
             for mm in mitre if (mm.get("technique_id") if isinstance(mm, dict)
                                 else mm.technique_id) == m["technique_id"]})}
            for m in mitre_context],
        "ueba_context": ueba_context,
        "unavailable": unavailable,
    }

    return {
        "incident": {
            "incident_id": incident.incident_id,
            "title": incident.title,
            "severity": incident.severity,
            "status": incident.status,
            "confidence": incident.confidence,
            "risk_score": incident.risk_score,
            "risk_band": incident.risk_band,
            "risk_explanation": incident.risk_explanation,
            "first_seen": _aware(incident.first_seen),
            "last_seen": _aware(incident.last_seen),
            "created_at": _aware(incident.created_at),
            "updated_at": _aware(incident.updated_at),
            "detection_count": len(dets),
            "evidence_count": len(set(incident.evidence_event_ids or [])),
        },
        "explanation": explanation,
        "timeline": timeline,
        "entities": entities,
        "detections": det_records,
        "evidence_sample": events,
        "evidence_total": len(set(incident.evidence_event_ids or [])),
        "mitre_techniques": mitre_context,
        "ueba": ueba_context,
        "missing_detections": missing,
        "risk": {
            "score": incident.risk_score,
            "band": incident.risk_band,
            "explanation": incident.risk_explanation,
            "breakdown": breakdown,
            "factors": risk_factors,
        },
    }
