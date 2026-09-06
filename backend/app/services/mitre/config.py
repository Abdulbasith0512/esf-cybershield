"""Risk configuration. Every weight, cap, and band lives here."""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class RiskConfig:
    # Severity base points.
    sev_base: dict = field(default_factory=lambda: {"LOW": 10, "MEDIUM": 25, "HIGH": 45, "CRITICAL": 60})
    # Points per distinct rule, capped.
    diversity_per_rule: int = 8
    diversity_cap: int = 24
    # Confidence contribution: int(10 * mean detection confidence).
    # Evidence: 1 point per unique event, capped.
    evidence_cap: int = 10
    # Contextual signals.
    ioc_points: int = 12
    process_points: int = 8
    # Transfer: scaled by bytes/threshold doublings, [transfer_min, transfer_max].
    transfer_min: int = 5
    transfer_step: int = 2
    transfer_max: int = 12
    # Sequence bonuses.
    chain3_points: int = 10
    chain4_points: int = 15
    # MITRE: per distinct tactic, capped.
    mitre_per_tactic: int = 3
    mitre_cap: int = 12
    # Bands: (upper_bound_inclusive, band).
    bands: tuple = ((24, "LOW"), (49, "MEDIUM"), (74, "HIGH"), (100, "CRITICAL"))


DEFAULT_RISK = RiskConfig()
