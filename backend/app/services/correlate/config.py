"""Correlator configuration. Weights, window, and tables live here — nowhere else."""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class CorrelatorConfig:
    # Temporal proximity: detections farther apart never link on time alone.
    window_minutes: int = 30
    # Network-aware FLOW correlation uses the same default through a separate
    # knob, so flow tuning never moves AUTH/PROC/NET/DATA behavior.
    network_window_minutes: int = 30
    # Recognized attack-sequence pairs (unordered). Strong correlation signal.
    sequence_pairs: tuple = field(default_factory=lambda: (
        ("AUTH-001", "PROC-001"), ("AUTH-001", "PROC-002"),
        ("AUTH-001", "NET-001"), ("PROC-001", "NET-001"),
        ("PROC-002", "NET-001"), ("PROC-001", "DATA-001"),
        ("PROC-002", "DATA-001"), ("NET-001", "DATA-001"),
        ("AUTH-001", "DATA-001"),
    ))
    # Justified FLOW sequence relationships (unordered): recon Scanner output
    # feeding brute-force attempts, and rate anomaly escalating to burst.
    flow_sequence_pairs: tuple = field(default_factory=lambda: (
        ("FLOW-003", "FLOW-002"), ("FLOW-001", "FLOW-006"),
    ))
    # Full-chain bonuses (subsets of member rule_ids).
    full_chain_3: frozenset = frozenset({"AUTH-001", "PROC-001", "NET-001"})
    full_chain_4: frozenset = frozenset({"AUTH-001", "PROC-001", "NET-001", "DATA-001"})
    # Transparent score weights (sum <= 1.0; see scoring formula in rules.py).
    w_same_user: float = 0.20
    w_same_host: float = 0.15
    w_temporal: float = 0.20
    w_shared_evidence: float = 0.25
    w_sequence: float = 0.15
    w_multi_rule: float = 0.05
    # Severity derivation (composition -> severity, evaluated top-down).
    sev_critical_rules: frozenset = frozenset({"AUTH-001", "PROC-001", "NET-001", "DATA-001"})


DEFAULT_CORRELATOR = CorrelatorConfig()
