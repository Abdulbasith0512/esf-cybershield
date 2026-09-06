"""Data-transfer rule: DATA-001. Deterministic threshold by design."""


from app.services.detect.config import DetectorConfig
from app.services.detect.models import DetectionResult, make_result


class AbnormalOutbound:
    """DATA-001 Abnormal Outbound Data Transfer (HIGH).

    Fires when a single transfer meets the byte threshold. Known limitation:
    it cannot distinguish scheduled backups from exfiltration — a legitimate
    bulky service job WILL trigger it. Baseline behavior comes later (UEBA).
    """

    rule_id = "DATA-001"
    name = "Abnormal Outbound Data Transfer"
    description = "Single outbound transfer at or above the byte threshold."
    severity = "HIGH"

    def __init__(self, config: DetectorConfig = DetectorConfig()):
        self.config = config

    def evaluate(self, events: list[dict]) -> list[DetectionResult]:
        out = []
        for e in events:
            if e.get("event_type") not in ("data_transfer", "network_connection"):
                continue
            sent = e.get("bytes_sent") or 0
            if sent < self.config.bytes_threshold:
                continue
            doublings, ratio = 0, sent / self.config.bytes_threshold
            while ratio >= 2:
                doublings += 1
                ratio /= 2
            out.append(make_result(
                self.rule_id, self.name, self.severity,
                min(0.75 + 0.05 * doublings, 0.95),
                (f"Outbound transfer of {sent:,} bytes by user '{e.get('user')}' "
                 f"on host '{e.get('host')}' meets the {self.config.bytes_threshold:,}-byte "
                 f"threshold. Volume alone does not prove malicious intent."),
                [e], {"user": e.get("user"), "host": e.get("host"),
                      "bytes_sent": sent, "threshold": self.config.bytes_threshold}))
        return out
