"""UEBA configuration. Every threshold, window, and hyperparameter lives here."""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class UebaConfig:
    # Aggregation: fixed UTC hour windows per user entity.
    window_hours: int = 1
    # Business hours (UTC) for unusual_hour_event_count.
    day_start_hour: int = 8
    day_end_hour: int = 20
    # Cold start: windows of history required before READY.
    min_history_windows: int = 5
    min_history_events: int = 10
    # IsolationForest hyperparameters (documented, not defaults-by-accident).
    # n_estimators=200: stable scores at 10k scale; contamination=0.05:
    # operational anomaly-rate choice (top 5% of train scores anomalous).
    random_state: int = 42
    n_estimators: int = 200
    contamination: float = 0.05
    # Versions. Bump on any behavior change.
    model_version: str = "ueba-iforest-v1"
    feature_version: str = "ueba-features-v1"
    # Feature columns, fixed order. Numeric behavioral aggregates only.
    feature_columns: tuple = field(default_factory=lambda: (
        "event_count", "auth_event_count", "failed_auth_count",
        "successful_auth_count", "failed_auth_ratio", "unique_source_ip_count",
        "new_source_ip_count", "unique_destination_count", "dns_event_count",
        "outbound_bytes_log1p", "process_event_count", "unusual_hour_event_count",
    ))


DEFAULT_UEBA = UebaConfig()
