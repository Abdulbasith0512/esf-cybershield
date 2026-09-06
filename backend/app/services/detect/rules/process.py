"""Process rules: PROC-001, PROC-002. Telemetry analysis only — nothing executes."""

from app.services.detect.config import DetectorConfig
from app.services.detect.models import DetectionResult, basename, make_result


class SuspiciousProcess:
    """PROC-001 Suspicious Process Execution (HIGH). Configured exact-match
    patterns only — no broad substring matching over process names."""

    rule_id = "PROC-001"
    name = "Suspicious Process Execution"
    description = "Process telemetry matching a configured suspicious pattern."
    severity = "HIGH"

    def __init__(self, config: DetectorConfig = DetectorConfig()):
        self.config = config

    def evaluate(self, events: list[dict]) -> list[DetectionResult]:
        out = []
        for e in events:
            if e.get("event_type") != "process_creation":
                continue
            proc, parent = basename(e.get("process_name")), basename(e.get("parent_process"))
            cmd = (e.get("command_line") or "").lower()
            for pat in self.config.sus_process_patterns:
                proc_hit = bool(pat["process"]) and proc in pat["process"]
                cmd_hit = bool(pat["cmdline_any"]) and any(t in cmd for t in pat["cmdline_any"])
                if not (proc_hit or cmd_hit):
                    continue
                if proc_hit and pat["parents"] and parent not in pat["parents"]:
                    continue
                out.append(make_result(
                    self.rule_id, self.name, self.severity, pat["confidence"],
                    (f"Process telemetry matched pattern '{pat['id']}': "
                     f"{pat['description']} (process='{proc}', parent='{parent}')."),
                    [e], {"pattern_id": pat["id"], "process": proc,
                          "parent": parent}))
                break
        return out


class SuspiciousParentChild:
    """PROC-002 Suspicious Parent-Child Relationship (HIGH)."""

    rule_id = "PROC-002"
    name = "Suspicious Parent-Child Process Relationship"
    description = "Configured suspicious parent->child process pair observed."
    severity = "HIGH"

    def __init__(self, config: DetectorConfig = DetectorConfig()):
        self.config = config
        self.pairs = set(config.sus_parent_child)

    def evaluate(self, events: list[dict]) -> list[DetectionResult]:
        out = []
        for e in events:
            if e.get("event_type") != "process_creation":
                continue
            proc, parent = basename(e.get("process_name")), basename(e.get("parent_process"))
            if (parent, proc) in self.pairs:
                out.append(make_result(
                    self.rule_id, self.name, self.severity, 0.8,
                    (f"Observed configured suspicious parent-child relationship: "
                     f"'{parent}' spawned '{proc}'."),
                    [e], {"parent": parent, "child": proc}))
        return out
