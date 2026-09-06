"""Rule registry. Engine executes these; no rule logic lives in the engine."""

from app.services.detect.config import DetectorConfig
from app.services.detect.rules.authentication import (
    BruteForceSuccess,
    NewSourceIp,
    UnusualLoginTime,
)
from app.services.detect.rules.data_transfer import AbnormalOutbound
from app.services.detect.rules.network import MassDns, SuspiciousDestination
from app.services.detect.rules.process import SuspiciousParentChild, SuspiciousProcess


def default_rules(config: DetectorConfig | None = None):
    config = config or DetectorConfig()
    return [
        BruteForceSuccess(config),
        UnusualLoginTime(config),
        NewSourceIp(config),
        SuspiciousProcess(config),
        SuspiciousParentChild(config),
        SuspiciousDestination(config),
        MassDns(config),
        AbnormalOutbound(config),
    ]
