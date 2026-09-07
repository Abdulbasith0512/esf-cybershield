"""Network-flow detector package. Separate registry; existing rules untouched."""

from app.services.detect.flow.config import DEFAULT_FLOW_CONFIG, FlowConfig
from app.services.detect.flow.engine import detect_flows
from app.services.detect.flow.rules import (
    ByteRateAnomaly,
    HighConnectionRate,
    PortScan,
    ProtocolPortNovelty,
    RepeatedAttempts,
    VolumeBurst,
)


def default_flow_rules(config: FlowConfig | None = None):
    config = config or FlowConfig()
    return [
        HighConnectionRate(config),
        RepeatedAttempts(config),
        PortScan(config),
        ByteRateAnomaly(config),
        ProtocolPortNovelty(config),
        VolumeBurst(config),
    ]


__all__ = [
    "ByteRateAnomaly",
    "DEFAULT_FLOW_CONFIG",
    "FlowConfig",
    "HighConnectionRate",
    "PortScan",
    "ProtocolPortNovelty",
    "RepeatedAttempts",
    "VolumeBurst",
    "default_flow_rules",
    "detect_flows",
]
