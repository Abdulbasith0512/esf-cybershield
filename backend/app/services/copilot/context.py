"""Structured copilot context. Pure builder over investigation-shaped data.

Only facts already present in the investigation view (plus threat-intel and
recommendation views derived from the same stored rows) enter the context.
Bounded everywhere; exact totals preserved alongside capped lists. Never
includes benchmark labels, secrets, raw payload blobs, or other incidents.
"""

from typing import Any

SUGGESTED_QUESTIONS: tuple[str, ...] = (
    "Summarize this incident",
    "Explain why this incident was created",
    "Walk me through the timeline",
    "What evidence supports this incident?",
    "What MITRE ATT&CK techniques are involved?",
    "What UEBA anomalies are relevant?",
    "What threat intelligence is available?",
    "What should I investigate next?",
)

MAX_CONTEXT_DETECTIONS = 100
MAX_CONTEXT_TIMELINE = 100
MAX_CONTEXT_REF_IDS = 25
MAX_CONTEXT_THREAT_INTEL = 100
MAX_CONTEXT_NOTES = 5
MAX_NOTE_CHARS = 500
MAX_CONTEXT_QUESTION_HISTORY = 4


def _head(values: list, limit: int) -> list:
    return list(values[:limit])


def _incident_block(investigation: dict[str, Any]) -> dict[str, Any]:
    incident = dict(investigation.get("incident") or {})
    return {
        "incident_id": incident.get("incident_id", ""),
        "title": incident.get("title", ""),
        "severity": incident.get("severity", ""),
        "status": incident.get("status", ""),
        "confidence": incident.get("confidence"),
        "risk_score": incident.get("risk_score"),
        "risk_band": incident.get("risk_band"),
        "first_seen": str(incident.get("first_seen", "")),
        "last_seen": str(incident.get("last_seen", "")),
        "detection_count": incident.get("detection_count", 0),
        "evidence_count": incident.get("evidence_count", 0),
    }


def _timeline_block(investigation: dict[str, Any]) -> list[dict[str, Any]]:
    entries = []
    for item in _head(list(investigation.get("timeline") or []), MAX_CONTEXT_TIMELINE):
        entries.append({
            "detection_id": item.get("detection_id", ""),
            "rule_id": item.get("rule_id", ""),
            "rule_name": item.get("rule_name", ""),
            "severity": item.get("severity", ""),
            "first_seen": str(item.get("first_seen", "")),
            "last_seen": str(item.get("last_seen", "")),
            "evidence_count": item.get("evidence_count", 0),
            "mitre_technique_ids": list(item.get("mitre_technique_ids") or []),
        })
    return entries


def _detections_block(investigation: dict[str, Any]) -> list[dict[str, Any]]:
    records = []
    for det in _head(list(investigation.get("detections") or []), MAX_CONTEXT_DETECTIONS):
        evidence = sorted(set(det.get("evidence_event_ids") or []))
        records.append({
            "detection_id": det.get("detection_id", ""),
            "rule_id": det.get("rule_id", ""),
            "rule_name": det.get("rule_name", ""),
            "severity": det.get("severity", ""),
            "confidence": det.get("confidence"),
            "reason": det.get("reason", ""),
            "first_seen": str(det.get("first_seen", "")),
            "last_seen": str(det.get("last_seen", "")),
            "evidence_event_ids": _head(evidence, MAX_CONTEXT_REF_IDS),
            "evidence_count": len(evidence),
            "mitre_technique_ids": list(det.get("mitre_technique_ids") or []),
        })
    return records


def _case_block(investigation: dict[str, Any]) -> dict[str, Any]:
    case = investigation.get("case") or {}
    notes = []
    for note in _head(list(case.get("notes") or []), MAX_CONTEXT_NOTES):
        body = str(note.get("body", ""))[:MAX_NOTE_CHARS]
        notes.append({"note_id": note.get("note_id", ""),
                      "author": note.get("author"), "body": body})
    return {
        "status": case.get("status", ""),
        "assignee": case.get("assignee"),
        "note_count": len(case.get("notes") or []),
        "notes": notes,
    }


def _threat_intel_block(enriched: list) -> list[dict[str, Any]]:
    items = []
    for entry in _head(list(enriched or []), MAX_CONTEXT_THREAT_INTEL):
        observable = entry.observable
        intel = entry.intelligence
        items.append({
            "type": observable.type,
            "value": observable.value,
            "normalized_value": observable.normalized_value,
            "source": observable.source,
            "event_count": observable.event_count,
            "available": entry.available,
            "provider": intel.provider if intel else "",
            "classification": intel.classification if intel else "unknown",
            "confidence": intel.confidence if intel else 0.0,
            "categories": list(intel.categories) if intel else [],
            "retrieved_at": str(intel.retrieved_at) if intel and intel.retrieved_at else None,
        })
    return items


def _recommendations_block(recommendations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    items = []
    for rec in recommendations or []:
        items.append({
            "id": rec.get("id", ""),
            "priority": rec.get("priority", ""),
            "category": rec.get("category", ""),
            "title": rec.get("title", ""),
            "reason": rec.get("reason", ""),
            "actions": list(rec.get("actions") or []),
        })
    return items


def build_copilot_context(investigation: dict[str, Any],
                          threat_intel: list | None = None,
                          recommendations: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Assemble the deterministic, bounded copilot context. Inputs untouched."""
    detections = list(investigation.get("detections") or [])
    timeline = list(investigation.get("timeline") or [])
    intel = list(threat_intel or [])
    return {
        "incident": _incident_block(investigation),
        "explanation": dict(investigation.get("explanation") or {}),
        "timeline": _timeline_block(investigation),
        "timeline_total": len(timeline),
        "entities": dict(investigation.get("entities") or {}),
        "detections": _detections_block(investigation),
        "detections_total": len(detections),
        "evidence_total": investigation.get("evidence_total", 0),
        "missing_detections": list(investigation.get("missing_detections") or []),
        "mitre_techniques": list(investigation.get("mitre_techniques") or []),
        "ueba": dict(investigation.get("ueba") or {}),
        "risk": dict(investigation.get("risk") or {}),
        "case": _case_block(investigation),
        "threat_intelligence": _threat_intel_block(intel),
        "threat_intelligence_total": len(intel),
        "recommendations": _recommendations_block(recommendations),
    }
