"""Citation extraction/validation and injection-signal detection.

Citations are the code-level grounding guarantee: whatever the provider
writes, only identifiers present in the copilot context survive into the
structured response. Incident text matching known injection phrasing is
detectable here so tests (and operators) can prove adversarial content was
present yet never acted upon.
"""

import re
from typing import Any

CITATION_RE = re.compile(
    r"\[(DET|EVID|MITRE|UEBA|TI):([A-Za-z0-9][A-Za-z0-9._: /-]{0,200})\]"
)

_INJECTION_RES = [
    re.compile(r"ignore\s+(all\s+)?prev(ious)?\s+instructions", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(prior|previous|system)\s+\w+", re.IGNORECASE),
    re.compile(r"\breport\b.{0,40}\bas\s+safe\b", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+", re.IGNORECASE),
    re.compile(r"override\s+(your|the)\s+policy", re.IGNORECASE),
]

_VALID_TYPES = ("detection", "event", "mitre", "ueba", "threat_intelligence")


def contains_injection(text: str | None) -> bool:
    """Heuristic signal for instruction-like phrasing in untrusted text."""
    if not text:
        return False
    return any(pattern.search(text) for pattern in _INJECTION_RES)


def _known_ids(context: dict[str, Any]) -> dict[str, dict[str, str]]:
    """Map citation kind -> {raw id -> canonical id} from context only."""
    detections = {d.get("detection_id", ""): d.get("detection_id", "")
                  for d in context.get("detections") or []}
    events: dict[str, str] = {}
    for det in context.get("detections") or []:
        for eid in det.get("evidence_event_ids") or []:
            events[eid] = eid
    mitre = {}
    for mapping in context.get("mitre_techniques") or []:
        tid = mapping.get("technique_id", "") if isinstance(mapping, dict) \
            else getattr(mapping, "technique_id", "")
        if tid:
            mitre[tid] = tid
    ueba: dict[str, str] = {}
    observations = (context.get("ueba") or {}).get("observations") \
        if isinstance(context.get("ueba"), dict) else None
    for observation in observations or []:
        key = observation.get("entity_key", "") if isinstance(observation, dict) \
            else getattr(observation, "entity_key", "")
        if key:
            ueba[key] = key
    intel = {}
    for entry in context.get("threat_intelligence") or []:
        value = entry.get("normalized_value", "") or entry.get("value", "")
        if value:
            intel[value] = value
    return {"DET": detections, "EVID": events, "MITRE": mitre,
            "UEBA": ueba, "TI": intel}


def _citation_type(kind: str) -> str:
    return {"DET": "detection", "EVID": "event", "MITRE": "mitre",
            "UEBA": "ueba", "TI": "threat_intelligence"}[kind]


def extract_citations(answer: str, context: dict[str, Any]) -> tuple[list[dict], int]:
    """Validate citation tags against context identifiers.

    Returns (valid citations in first-seen order, dropped count).
    Conversation history can never mint citations: only context IDs qualify.
    """
    known = _known_ids(context)
    valid: list[dict] = []
    seen: set[tuple[str, str]] = set()
    dropped = 0
    for match in CITATION_RE.finditer(answer or ""):
        kind, raw = match.group(1), match.group(2).strip()
        canonical = (known.get(kind) or {}).get(raw)
        if canonical is None or (kind, canonical) in seen:
            dropped += 1
            continue
        seen.add((kind, canonical))
        valid.append({"type": _citation_type(kind), "id": canonical,
                      "label": f"{kind}:{canonical}"})
    return valid, dropped
