"""Central rule configuration. No thresholds scattered in rule code."""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class DetectorConfig:
    # AUTH-001
    brute_min_fails: int = 3
    brute_window_minutes: int = 10
    # AUTH-002
    login_day_start_hour: int = 8
    login_day_end_hour: int = 20
    # AUTH-003
    new_ip_min_history: int = 3
    # NET-001
    ioc_path: str = "data/iocs.json"  # relative to detect/ package dir
    # NET-002
    dns_threshold: int = 100
    dns_window_minutes: int = 5
    # DATA-001
    bytes_threshold: int = 1_000_000_000  # 1 GB
    # PROC-001 / PROC-002 patterns
    sus_process_patterns: tuple = field(default_factory=lambda: (
        {"id": "P1-shell-from-service",
         "process": ("powershell.exe", "pwsh.exe", "cmd.exe"),
         "parents": ("services.exe", "svchost.exe", "wmiprvse.exe"),
         "cmdline_any": (),
         "confidence": 0.75,
         "description": "interactive shell spawned by a service host process"},
        {"id": "P2-encoded-indicator",
         "process": (),
         "parents": (),
         "cmdline_any": ("-encodedcommand", "-enc ", "frombase64string"),
         "confidence": 0.85,
         "description": "encoded-command indicator in command-line telemetry"},
    ))
    sus_parent_child: tuple = field(default_factory=lambda: (
        ("services.exe", "powershell.exe"),
        ("services.exe", "cmd.exe"),
        ("svchost.exe", "powershell.exe"),
        ("svchost.exe", "cmd.exe"),
        ("winword.exe", "powershell.exe"),
        ("excel.exe", "powershell.exe"),
    ))


DEFAULT_CONFIG = DetectorConfig()
