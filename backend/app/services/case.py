"""Incident case management: lifecycle, assignment, notes, activity.

Metadata-only layer around incidents. Never touches security events,
detections, fingerprints, evidence, MITRE mappings, UEBA scores, or risk
calculations. Status changes never reinterpret detection truth.
"""

import uuid

STATUSES = ("NEW", "INVESTIGATING", "CONTAINED", "RESOLVED")

TRANSITIONS: dict[str, tuple[str, ...]] = {
    "NEW": ("INVESTIGATING",),
    "INVESTIGATING": ("CONTAINED", "RESOLVED"),
    "CONTAINED": ("INVESTIGATING", "RESOLVED"),
    "RESOLVED": (),
}

NOTE_MAX_LENGTH = 5000
IDENTIFIER_MAX_LENGTH = 128

ACTIONS = ("STATUS_CHANGED", "ASSIGNED", "UNASSIGNED", "NOTE_ADDED")


def is_valid_status(value: object) -> bool:
    return isinstance(value, str) and value in STATUSES


def allowed_transitions(status: str) -> list[str]:
    return list(TRANSITIONS.get(status, ()))


def validate_transition(current: str, target: object) -> str:
    """Return the normalized target or raise ValueError with a clear reason."""
    if not is_valid_status(target):
        raise ValueError(f"invalid status {target!r}; expected one of {', '.join(STATUSES)}")
    assert isinstance(target, str)
    if target not in TRANSITIONS.get(current, ()):
        raise ValueError(f"invalid transition {current!r} -> {target!r}; "
                         f"allowed: {', '.join(TRANSITIONS.get(current, ())) or 'none'}")
    return target


def normalize_identifier(value: object, field: str) -> str | None:
    """Opaque analyst identifier: non-empty bounded string, or None to clear."""
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"invalid {field}: expected a non-empty string or null")
    cleaned = value.strip()
    if len(cleaned) > IDENTIFIER_MAX_LENGTH:
        raise ValueError(f"invalid {field}: exceeds {IDENTIFIER_MAX_LENGTH} characters")
    return cleaned


def normalize_note_body(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("invalid note body: expected non-empty plain text")
    body = value.strip()
    if len(body) > NOTE_MAX_LENGTH:
        raise ValueError(f"invalid note body: exceeds {NOTE_MAX_LENGTH} characters")
    return body


def new_note_id() -> str:
    return f"note-{uuid.uuid4().hex[:12]}"


def new_activity_id() -> str:
    return f"act-{uuid.uuid4().hex[:12]}"
