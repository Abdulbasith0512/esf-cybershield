"""UEBA result contracts."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

BaselineStatus = Literal["READY", "COLD_START", "INSUFFICIENT_HISTORY"]


class Observation(BaseModel):
    """One (user, hour-window) behavioral observation. Internal to the pipeline."""

    entity_key: str
    window_start: datetime
    features: dict[str, float]
    event_ids: list[str] = Field(default_factory=list)


class UebaAnomalyResult(BaseModel):
    entity_key: str
    observation_time: datetime
    anomaly_score: float = Field(ge=0.0, le=1.0)
    anomaly_flag: bool
    model_version: str
    feature_version: str
    metadata: dict[str, Any] = Field(default_factory=dict)
