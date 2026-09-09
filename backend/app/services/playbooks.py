"""Analyst response recommendations. Read-only guidance over stored incidents.

Pure function over the investigation view: same incident state always yields
the same recommendations in the same order. Advisory only — nothing here
executes containment, touches telemetry, or resolves incidents. Language is
deliberately hedged (investigate/validate/review/consider); techniques and
rules referenced are the ones already stored on the incident.
"""

from typing import Any

_SEV_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

_NETWORK_RULE_PREFIXES = ("FLOW-", "NET-", "DATA-")
_ENDPOINT_RULE_MARKERS = ("PROC-",)
_IDENTITY_RULE_MARKERS = ("AUTH-",)

_MAX_REF_IDS = 25
_MAX_REF_EVIDENCE = 10

_RULE_GUIDANCE: dict[str, dict[str, Any]] = {
    "FLOW-001": {
        "title": "Investigate high connection-rate activity",
        "actions": [
            "Identify the dominant source and destination endpoints in the evidence sample.",
            "Validate whether the burst matches expected traffic for the destination service.",
            "Review whether the rate persists beyond the detection window before escalating.",
        ],
    },
    "FLOW-002": {
        "title": "Investigate repeated connection attempts",
        "actions": [
            "Inspect the target service and destination port.",
            "Review the unanswered-connection pattern against expected client retries.",
            "Validate whether the source is an authorized scanner or tester.",
        ],
    },
    "FLOW-003": {
        "title": "Investigate potential scanning behavior",
        "actions": [
            "Review the source and the spread of destination ports.",
            "Validate whether scanning from this source is authorized activity.",
            "Check whether contacted services responded or stayed silent.",
        ],
    },
    "FLOW-004": {
        "title": "Investigate unusual byte-rate behavior",
        "actions": [
            "Inspect the large-transfer source and destination endpoints.",
            "Validate whether the transfer matches expected bulk-transfer activity.",
            "Compare transfer size against the destination's recent baseline.",
        ],
    },
    "FLOW-005": {
        "title": "Investigate novel protocol/port relationship",
        "actions": [
            "Validate whether the observed service relationship is expected in this environment.",
            "Review when the protocol/port combination first appeared.",
            "Check whether similar pairs recur across other hosts.",
        ],
    },
    "FLOW-006": {
        "title": "Investigate high-volume burst behavior",
        "actions": [
            "Identify the affected destination and measure burst duration.",
            "Consider containment of the affected asset after validating the activity.",
            "Review upstream traffic sources feeding the burst.",
        ],
    },
}


def _priority_for(severity: str) -> str:
    rank = _SEV_RANK.get((severity or "").upper(), 0)
    if rank >= 2:
        return "HIGH"
    if rank == 1:
        return "MEDIUM"
    return "LOW"


def _head(values: list, limit: int) -> list:
    return list(values[:limit])


def _rule_detections(detections: list[dict], rule_id: str) -> list[dict]:
    return sorted(
        (d for d in detections if d.get("rule_id") == rule_id),
        key=lambda d: d.get("detection_id", ""),
    )


def recommend(investigation: dict[str, Any]) -> list[dict[str, Any]]:
    """Build deterministic recommendations from an investigation view.

    The input is never mutated. Callers must pass post-detection,
    label-free investigation data (see services.investigate).
    """
    incident = investigation.get("incident") or {}
    detections = list(investigation.get("detections") or [])
    entities = investigation.get("entities") or {}
    mitre = list(investigation.get("mitre_techniques") or [])
    ueba = investigation.get("ueba") or {}
    severity = incident.get("severity") or "LOW"
    incident_id = incident.get("incident_id", "")

    src_ips = list(entities.get("source_ips") or [])
    dst_ips = list(entities.get("destination_ips") or [])
    rules_present = sorted({d.get("rule_id", "") for d in detections if d.get("rule_id")})
    network_rules = sorted(r for r in rules_present
                           if r.startswith(_NETWORK_RULE_PREFIXES))
    has_endpoint = bool(entities.get("processes")) or \
        any(r.startswith(_ENDPOINT_RULE_MARKERS) for r in rules_present)
    has_identity = bool(entities.get("users")) or \
        any(r.startswith(_IDENTITY_RULE_MARKERS) for r in rules_present)

    recs: list[dict[str, Any]] = []

    det_ids = sorted(d.get("detection_id", "") for d in detections if d.get("detection_id"))
    ev_ids: list[str] = []
    for det in detections:
        ev_ids.extend(det.get("evidence_event_ids") or [])
    ev_ids = sorted(set(ev_ids))
    entity_bits = []
    if src_ips:
        entity_bits.append(f"sources {', '.join(src_ips[:3])}")
    if dst_ips:
        entity_bits.append(f"destinations {', '.join(dst_ips[:3])}")
    recs.append({
        "id": "rec-triage",
        "priority": _priority_for(severity),
        "category": "TRIAGE",
        "title": "Triage the incident timeline",
        "reason": (f"Incident '{incident.get('title', incident_id)}' groups "
                   f"{len(detections)} detection(s)"
                   + (f" involving {entity_bits[0]}" if entity_bits else "") + "."),
        "actions": [
            "Review the ordered detection timeline from earliest to latest.",
            "Identify the source and destination entities involved.",
            "Confirm whether the observed activity is expected in this environment.",
        ],
        "evidence_refs": {"detection_ids": _head(det_ids, _MAX_REF_IDS),
                          "detection_count": len(det_ids),
                          "evidence_event_ids": _head(ev_ids, _MAX_REF_EVIDENCE),
                          "evidence_count": len(ev_ids)},
    })

    for rule_id in network_rules:
        guidance = _RULE_GUIDANCE.get(rule_id)
        if guidance is None:
            continue
        members = _rule_detections(detections, rule_id)
        member_ids = [d.get("detection_id", "") for d in members]
        member_ev = sorted({eid for d in members for eid in (d.get("evidence_event_ids") or [])})
        sev = max([m.get("severity", "LOW") for m in members] or ["LOW"],
                  key=lambda s: _SEV_RANK.get(str(s).upper(), 0))
        recs.append({
            "id": f"rec-network-{rule_id}",
            "priority": _priority_for(sev),
            "category": "NETWORK",
            "title": guidance["title"],
            "reason": (f"{len(members)} {rule_id} detection(s) observed; review the "
                       f"network behavior before drawing conclusions."),
            "actions": list(guidance["actions"]),
            "evidence_refs": {"detection_ids": _head(member_ids, _MAX_REF_IDS),
                              "detection_count": len(member_ids),
                              "evidence_event_ids": _head(member_ev, _MAX_REF_EVIDENCE),
                              "evidence_count": len(member_ev)},
        })

    if has_endpoint:
        recs.append({
            "id": "rec-endpoint",
            "priority": _priority_for(severity),
            "category": "ENDPOINT",
            "title": "Investigate endpoint context",
            "reason": "Process or endpoint telemetry is associated with this incident.",
            "actions": [
                "Review the process associated with the event where available.",
                "Inspect host telemetry around the detection timestamps.",
                "Validate whether the process behavior is expected on the host.",
            ],
            "evidence_refs": {"detection_ids": _head(det_ids, _MAX_REF_IDS),
                              "detection_count": len(det_ids),
                              "evidence_event_ids": _head(ev_ids, _MAX_REF_EVIDENCE),
                              "evidence_count": len(ev_ids)},
        })

    if has_identity:
        recs.append({
            "id": "rec-identity",
            "priority": _priority_for(severity),
            "category": "IDENTITY",
            "title": "Investigate authentication context",
            "reason": "User or authentication context is associated with this incident.",
            "actions": [
                "Review the user or identity associated with the detections.",
                "Validate whether the authentication activity is expected for the identity.",
                "Check for related authentication events outside this incident window.",
            ],
            "evidence_refs": {"detection_ids": _head(det_ids, _MAX_REF_IDS),
                              "detection_count": len(det_ids),
                              "evidence_event_ids": _head(ev_ids, _MAX_REF_EVIDENCE),
                              "evidence_count": len(ev_ids)},
        })

    for mapping in sorted(mitre, key=lambda m: (m.get("technique_id", ""))):
        tid = mapping.get("technique_id", "")
        linked = sorted({d.get("detection_id", "") for d in detections
                         if d.get("rule_id") == mapping.get("source_rule_id")})
        recs.append({
            "id": f"rec-mitre-{tid}",
            "priority": _priority_for(severity),
            "category": "MITRE",
            "title": f"Investigate technique {tid}",
            "reason": mapping.get("rationale") or f"Mapped technique {tid}.",
            "actions": [
                f"Review {mapping.get('technique_name', tid)} guidance for defenders.",
                "Validate whether the mapped behavior matches the technique pattern.",
                "Scope which additional hosts or identities show the same pattern.",
            ],
            "evidence_refs": {"detection_ids": _head(linked, _MAX_REF_IDS),
                              "detection_count": len(linked),
                              "evidence_event_ids": [],
                              "evidence_count": 0,
                              "technique_id": tid},
        })

    if ueba.get("available") and ueba.get("anomaly_flag"):
        recs.append({
            "id": "rec-ueba",
            "priority": _priority_for(severity),
            "category": "UEBA",
            "title": "Investigate behavioral anomaly",
            "reason": "A UEBA anomaly is associated with this incident.",
            "actions": [
                "Review the anomalous entity and its anomaly score.",
                "Inspect surrounding activity for the entity.",
                "Compare anomaly timing with incident detection timestamps.",
            ],
            "evidence_refs": {"detection_ids": _head(det_ids, _MAX_REF_IDS),
                              "detection_count": len(det_ids),
                              "evidence_event_ids": _head(ev_ids, _MAX_REF_EVIDENCE),
                              "evidence_count": len(ev_ids)},
        })

    if str(severity).upper() in ("HIGH", "CRITICAL"):
        recs.append({
            "id": "rec-containment",
            "priority": "HIGH" if str(severity).upper() == "CRITICAL" else "MEDIUM",
            "category": "CONTAINMENT",
            "title": "Consider containment after validation",
            "reason": (f"Severity is {str(severity).upper()}; containment may be warranted "
                       f"once activity is validated. Advisory only — nothing is executed."),
            "actions": [
                "Validate that the activity is not expected before acting.",
                "Consider containment of the affected asset after validation.",
                "Record the containment decision in an incident note.",
            ],
            "evidence_refs": {"detection_ids": _head(det_ids, _MAX_REF_IDS),
                              "detection_count": len(det_ids),
                              "evidence_event_ids": _head(ev_ids, _MAX_REF_EVIDENCE),
                              "evidence_count": len(ev_ids)},
        })

    return recs
