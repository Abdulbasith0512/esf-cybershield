"""Stable fingerprint construction for incidents.

Fingerprint = "incident:" + comma-joined sorted detection IDs.
The incident_id is UUIDv5 over that fingerprint (see models.py).
Same detection membership -> same fingerprint -> same incident ID.
Different membership -> different ID by construction.
"""

from app.services.correlate.models import incident_id_for


def group_fingerprint(detection_ids: list[str]) -> str:
    return f"incident:{','.join(sorted(detection_ids))}"


__all__ = ["group_fingerprint", "incident_id_for"]
