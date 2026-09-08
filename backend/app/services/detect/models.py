"""DetectionResult contract + shared deterministic helpers."""

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
NAMESPACE = uuid.UUID("7d3f9a1b-4c2e-5f8a-b6d4-1e9c3a5f7b22")


class DetectionResult(BaseModel):
    """One explainable analytical signal. NOT an incident."""

    detection_id: str
    rule_id: str
    rule_name: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str
    evidence_event_ids: list[str] = Field(min_length=1)
    bucket_event_ids: list[str] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        return f"{self.rule_id}:{','.join(sorted(self.evidence_event_ids))}"


def fingerprint(rule_id: str, evidence_ids: list[str]) -> str:
    return f"{rule_id}:{','.join(sorted(evidence_ids))}"


def detection_id_for(rule_id: str, evidence_ids: list[str]) -> str:
    """Deterministic ID: identical evidence always yields identical ID."""
    return str(uuid.uuid5(NAMESPACE, fingerprint(rule_id, evidence_ids)))


def make_result(rule_id: str, rule_name: str, severity: Severity,
                 confidence: float, reason: str, evidence: list[dict],
                 metadata: dict | None = None,
                 bucket: list[dict] | None = None) -> DetectionResult:
    ids = sorted(e["event_id"] for e in evidence)
    stamps = sorted(e["_ts"] for e in evidence)
    bucket_ids = sorted({e["event_id"] for e in bucket} if bucket is not None else [])
    return DetectionResult(
        detection_id=detection_id_for(rule_id, ids),
        rule_id=rule_id, rule_name=rule_name, severity=severity,
        confidence=round(max(0.0, min(1.0, confidence)), 3),
        reason=reason, evidence_event_ids=ids,
        bucket_event_ids=bucket_ids,
        first_seen=stamps[0], last_seen=stamps[-1],
        metadata=metadata or {},
    )


def basename(path: str | None) -> str:
    if not path:
        return ""
    return path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1].lower()
