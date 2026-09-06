"""Rule-to-technique map. Rationale and confidence per mapping; catalog holds
technique definitions. AUTH-002 / NET-002 deliberately unmapped."""

import json
from pathlib import Path

with open(Path(__file__).parent / "catalog.json", encoding="utf-8") as _f:
    _CATALOG = json.load(_f)

CATALOG_VERSION: str = _CATALOG["catalog_version"]
TECHNIQUES: dict[str, dict] = {t["technique_id"]: t for t in _CATALOG["techniques"]}

RULE_TO_MITRE: dict[str, list[dict]] = {
    "AUTH-001": [
        {"technique_id": "T1110", "confidence": 0.85,
         "rationale": ("Multiple failed authentications followed by success for "
                       "the same identity matches brute-force behavior; potential "
                       "association, not proof the technique was used.")},
    ],
    "AUTH-003": [
        {"technique_id": "T1078", "confidence": 0.55,
         "rationale": ("Authentication from a previously unseen source is "
                       "consistent with valid-account use from a new location; "
                       "window-relative signal only, moderate confidence.")},
    ],
    "PROC-001": [
        {"technique_id": "T1059", "confidence": 0.8,
         "rationale": ("Shell process spawned by a service host matches command "
                       "interpreter abuse patterns; potential association only."),
         "patterns": ["P1-shell-from-service"]},
        {"technique_id": "T1140", "confidence": 0.75,
         "rationale": ("Encoded-command indicator in telemetry matches deobfuscation "
                       "behavior; potential association only."),
         "patterns": ["P2-encoded-indicator"]},
    ],
    "PROC-002": [
        {"technique_id": "T1059", "confidence": 0.8,
         "rationale": ("Configured suspicious parent-child pair (e.g. service host "
                       "spawning a shell) matches interpreter abuse; potential "
                       "association only.")},
    ],
    "NET-001": [
        {"technique_id": "T1071", "confidence": 0.7,
         "rationale": ("Connection to a controlled indicator over an application "
                       "protocol is consistent with C2 channel behavior; the "
                       "indicator is lab-controlled, so this is a hypothesis.")},
    ],
    "DATA-001": [
        {"technique_id": "T1048", "confidence": 0.6,
         "rationale": ("Unusually large outbound transfer is consistent with "
                       "exfiltration staging; volume alone does not prove "
                       "exfiltration.")},
    ],
}

UNMAPPED: dict[str, str] = {
    "AUTH-002": "Off-hours login is a behavioral heuristic, not a technique signature.",
    "NET-002": "DNS volume alone supports no specific technique; never labeled tunneling.",
}
