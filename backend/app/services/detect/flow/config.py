"""Central flow-rule configuration. No thresholds scattered in rule code."""

from dataclasses import dataclass


@dataclass(frozen=True)
class FlowConfig:
    # Shared
    event_type: str = "network_connection"
    # FLOW-001
    rate_window_seconds: int = 60
    rate_min_count: int = 50
    rate_baseline_factor: float = 5.0
    rate_baseline_windows: int = 10
    # FLOW-002
    brute_window_minutes: int = 5
    brute_min_flows: int = 20
    brute_max_bytes: int = 10 * 1024
    # FLOW-003
    scan_window_minutes: int = 5
    scan_min_ports: int = 15
    # Shannon entropy ceiling for the weak flow-only fallback. Provisional;
    # to be calibrated on benign traffic in the evaluation slice.
    scan_entropy_threshold: float = 4.0
    # FLOW-004
    byte_window_seconds: int = 60
    byte_baseline_minutes: int = 30
    byte_min_history_buckets: int = 5
    byte_ratio: float = 8.0
    byte_floor: float = 1_000_000.0
    # FLOW-005
    novelty_min_flows: int = 5
    # A novel pair must also carry meaningful minute-level volume: peak flows
    # in its busiest UTC minute bucket. Same 60-second volume floor the engine
    # treats as analyst-meaningful for rate anomalies; transient churn never
    # reaches it, so routine ephemeral-port novelty stays silent.
    novelty_min_peak: int = 50
    # IANA dynamic/private range, used only to flag ephemeral-destination
    # pairs in metadata (no behavioral effect in v1).
    ephemeral_port_min: int = 49152
    ephemeral_port_max: int = 65535
    # FLOW-006
    burst_window_seconds: int = 30
    burst_min_flows: int = 500
    burst_min_pps: float = 50_000.0


DEFAULT_FLOW_CONFIG = FlowConfig()
