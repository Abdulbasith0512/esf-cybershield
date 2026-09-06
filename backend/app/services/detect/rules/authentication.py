"""Authentication rules: AUTH-001, AUTH-002, AUTH-003."""

from datetime import timedelta

from app.services.detect.config import DetectorConfig
from app.services.detect.models import DetectionResult, make_result

# Status vocabulary as emitted by Slice 1/2 telemetry ("failed", not "failure").
FAIL_STATUSES = {"failed", "failure"}
SUCCESS_STATUSES = {"success", "successful", "succeeded"}


class BruteForceSuccess:
    """AUTH-001 Brute Force Followed By Successful Login (HIGH)."""

    rule_id = "AUTH-001"
    name = "Brute Force Followed By Successful Login"
    description = ("Multiple failed authentications followed by a success for "
                   "the same user within a time window.")
    severity = "HIGH"

    def __init__(self, config: DetectorConfig = DetectorConfig()):
        self.config = config

    def evaluate(self, events: list[dict]) -> list[DetectionResult]:
        auth = [e for e in events if e.get("event_type") == "authentication"
                and e.get("user")]
        groups: dict[tuple, list[dict]] = {}
        for e in auth:
            # Prefer user+IP; fall back to user+host when IP absent (documented).
            anchor = e.get("source_ip") or f"host:{e.get('host') or 'unknown'}"
            groups.setdefault((e["user"], anchor), []).append(e)
        out, seen_success = [], set()
        window = timedelta(minutes=self.config.brute_window_minutes)
        for (user, anchor), rows in groups.items():
            rows.sort(key=lambda r: r["_ts"])
            for i, s in enumerate(rows):
                if s.get("status") not in SUCCESS_STATUSES or s["event_id"] in seen_success:
                    continue
                fails = [r for r in rows[:i]
                         if r.get("status") in FAIL_STATUSES
                         and timedelta(0) <= s["_ts"] - r["_ts"] <= window]
                if len(fails) >= self.config.brute_min_fails:
                    seen_success.add(s["event_id"])
                    n = len(fails)
                    out.append(make_result(
                        self.rule_id, self.name, self.severity,
                        min(0.60 + 0.08 * n, 0.95),
                        (f"{n} failed authentication attempts for user '{user}' "
                         f"from {anchor} were followed by a successful authentication "
                         f"within {self.config.brute_window_minutes} minutes."),
                        fails + [s],
                        {"user": user, "anchor": anchor,
                         "fail_count": n, "same_ip": bool(s.get("source_ip"))}))
        return out


class UnusualLoginTime:
    """AUTH-002 Unusual Login Time (MEDIUM). Business-hour heuristic only."""

    rule_id = "AUTH-002"
    name = "Unusual Login Time"
    description = "Successful authentication outside the configured day window."
    severity = "MEDIUM"

    def __init__(self, config: DetectorConfig = DetectorConfig()):
        self.config = config

    def evaluate(self, events: list[dict]) -> list[DetectionResult]:
        out = []
        for e in events:
            if e.get("event_type") != "authentication" or e.get("status") not in SUCCESS_STATUSES:
                continue
            hour = e["_ts"].hour
            if self.config.login_day_start_hour <= hour < self.config.login_day_end_hour:
                continue
            deep = 0 <= hour <= 5
            out.append(make_result(
                self.rule_id, self.name, self.severity,
                0.65 if deep else 0.55,
                (f"Authentication occurred outside the configured normal login "
                 f"window ({self.config.login_day_start_hour:02d}:00-"
                 f"{self.config.login_day_end_hour:02d}:00 UTC); observed at "
                 f"{hour:02d}:{e['_ts'].minute:02d} UTC. This is not by itself "
                 f"evidence of compromise."),
                [e], {"user": e.get("user"), "observed_hour": hour}))
        return out


class NewSourceIp:
    """AUTH-003 New Source IP For User (MEDIUM). Window-relative only."""

    rule_id = "AUTH-003"
    name = "New Source IP For User"
    description = ("Authentication from a source IP unseen for the user in the "
                   "supplied telemetry window.")
    severity = "MEDIUM"

    def __init__(self, config: DetectorConfig = DetectorConfig()):
        self.config = config

    def evaluate(self, events: list[dict]) -> list[DetectionResult]:
        seen: dict[str, set] = {}
        counts: dict[str, int] = {}
        out = []
        for e in events:  # engine supplies timestamp-sorted rows
            if e.get("event_type") != "authentication" or not e.get("user"):
                continue
            user, ip = e["user"], e.get("source_ip")
            counts[user] = counts.get(user, 0) + 1
            known = seen.setdefault(user, set())
            if ip and ip not in known and counts[user] > self.config.new_ip_min_history \
                    and len(known) > 0:
                out.append(make_result(
                    self.rule_id, self.name, self.severity, 0.6,
                    (f"New source IP observed for user '{user}' within supplied "
                     f"telemetry (first {counts[user] - 1} events used as history). "
                     f"This is not by itself evidence of compromise."),
                    [e], {"user": user, "new_ip": ip,
                          "history_events": counts[user] - 1}))
            if ip:
                known.add(ip)
        return out
