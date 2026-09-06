"""Network rules: NET-001 (local IOC list), NET-002 (DNS volume). No live TI."""

import json
from datetime import timedelta
from pathlib import Path

from app.services.detect.config import DetectorConfig
from app.services.detect.models import DetectionResult, make_result


def load_iocs(path: str | None = None) -> list[dict]:
    p = Path(path) if path else Path(__file__).parent.parent / "data" / "iocs.json"
    return json.loads(p.read_text(encoding="utf-8"))["indicators"]


class SuspiciousDestination:
    """NET-001 Suspicious External Destination (HIGH). Local fixture only."""

    rule_id = "NET-001"
    name = "Suspicious External Destination"
    description = "Connection to a destination on the local controlled IOC list."
    severity = "HIGH"

    def __init__(self, config: DetectorConfig = DetectorConfig()):
        self.config = config
        self.iocs = load_iocs(config.ioc_path if Path(config.ioc_path).is_absolute()
                              else None)

    def evaluate(self, events: list[dict]) -> list[DetectionResult]:
        out = []
        for e in events:
            if e.get("event_type") not in ("network_connection", "dns_query", "data_transfer"):
                continue
            dip = (e.get("destination_ip") or "").strip()
            dom = (e.get("domain") or "").strip().lower()
            for ioc in self.iocs:
                hit = (ioc["type"] == "ip" and dip == ioc["indicator"]) or \
                      (ioc["type"] == "domain" and dom == ioc["indicator"].lower())
                if hit:
                    out.append(make_result(
                        self.rule_id, self.name, self.severity,
                        min(max(ioc.get("confidence", 0.8), 0.0), 1.0),
                        (f"Connection to controlled indicator {ioc['indicator']} "
                         f"({ioc['type']}): {ioc['description']}."),
                        [e], {"matched_ioc": ioc, "event_id": e["event_id"]}))
                    break
        return out


class MassDns:
    """NET-002 Mass DNS Activity (MEDIUM). Volume only — never 'tunneling'."""

    rule_id = "NET-002"
    name = "Mass DNS Activity"
    description = "High-volume DNS queries for one host/user in a short window."
    severity = "MEDIUM"

    def __init__(self, config: DetectorConfig = DetectorConfig()):
        self.config = config

    def evaluate(self, events: list[dict]) -> list[DetectionResult]:
        dns = [e for e in events if e.get("event_type") == "dns_query"]
        groups: dict[tuple, list[dict]] = {}
        for e in dns:
            groups.setdefault((e.get("host") or "unknown", e.get("user") or "unknown"), []).append(e)
        out = []
        window = timedelta(minutes=self.config.dns_window_minutes)
        for (host, user), rows in groups.items():
            rows.sort(key=lambda r: r["_ts"])
            start = 0
            for end in range(len(rows)):
                while rows[end]["_ts"] - rows[start]["_ts"] > window:
                    start += 1
                n = end - start + 1
                if n >= self.config.dns_threshold:
                    evidence = rows[start:end + 1]
                    out.append(make_result(
                        self.rule_id, self.name, self.severity,
                        min(0.6 + n / 1000, 0.9),
                        (f"High-volume DNS activity detected: {n} queries for "
                         f"host '{host}' / user '{user}' within "
                         f"{self.config.dns_window_minutes} minutes."),
                        evidence, {"host": host, "user": user, "count": n}))
                    start = end + 1  # non-overlapping windows, no dupes
        return out
