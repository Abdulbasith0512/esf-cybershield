# Detection Engine (Slice 3)

Deterministic rule engine over normalized `SecurityEvent` telemetry.
**Detection ≠ Incident**: a detection is one analytical signal with evidence.
Incidents (correlation of multiple signals) come later.

## Architecture

```
events (list[dict]) -> engine.detect()
  -> prepare(): copy, coerce timestamps to naive UTC, sort by time
  -> each registered Rule.evaluate(rows) -> DetectionResult list
  -> dedupe by fingerprint -> sorted results
```

- Package: `backend/app/services/detect/` (`models`, `config`, `common`,
  `engine`, `registry`, `rules/{authentication,process,network,data_transfer}`,
  `data/iocs.json`).
- Rules implement the `Rule` protocol (`rule_id/name/description/severity` +
  `evaluate`). The engine holds no rule logic; one failing rule cannot kill a run.
- Input: plain dicts (ORM rows, API payloads, or JSONL records all work).
  Inputs are copied, never modified; `raw_event` is never read.
- No DB writes, no incidents, no ML, no LLM. Stdlib + pydantic only.

## DetectionResult

`detection_id` (UUIDv5, deterministic), `rule_id`, `rule_name`,
`severity` ∈ LOW/MEDIUM/HIGH/CRITICAL, `confidence` ∈ [0,1],
`reason` (human explanation), `evidence_event_ids` (mandatory, sorted),
`first_seen`/`last_seen`, `metadata` (rule-specific context, e.g. matched IOC).

## Rule catalog

| ID | Name | Sev | Logic | Confidence |
|---|---|---|---|---|
| AUTH-001 | Brute Force → Success | HIGH | ≥3 fails + success, same user + IP (fallback user+host), 10-min window, one detection per success | 0.60+0.08/fail, cap 0.95 |
| AUTH-002 | Unusual Login Time | MEDIUM | success outside 08:00–20:00 UTC; “not compromise” language | 0.65 deep-night else 0.55 |
| AUTH-003 | New Source IP For User | MEDIUM | IP unseen in supplied window, ≥3 prior events; window-relative language | 0.60 |
| PROC-001 | Suspicious Process Execution | HIGH | exact-match patterns (shell-from-service-host; encoded-cmdline tokens); parent constraint enforced | per-pattern 0.75/0.85 |
| PROC-002 | Suspicious Parent-Child | HIGH | configured pair list (`services→powershell`, …), exact basename match | 0.80 |
| NET-001 | Suspicious External Destination | HIGH | local `iocs.json` (doc-range IP, `.invalid` domain); returns matched record | IOC confidence |
| NET-002 | Mass DNS Activity | MEDIUM | ≥100 DNS per host/user in 5 min, non-overlapping windows; “high-volume” language only | 0.6+n/1000, cap 0.9 |
| DATA-001 | Abnormal Outbound Transfer | HIGH | single transfer ≥1 GB | 0.75+0.05/doubling, cap 0.95 |

Config: `DetectorConfig` (thresholds, windows, login hours, IOC path, patterns).
Dedup: `rule_id + sorted evidence ids` fingerprint; `detection_id` = UUIDv5 of it.
Out-of-order: engine sorts by timestamp before evaluation; verified identical output on reversed input.

## Known limitations

- DATA-001 is volume-only: a legitimate bulky service job triggers it (UEBA baselines later).
- AUTH-003 is window-relative: “new” means unseen in *supplied* events, not globally.
- AUTH-002 uses fixed hours, not per-user baselines (UEBA later).
- PROC-001/002 only know configured patterns; novel tradecraft is invisible.
- Rules never read `raw_event`, so `scenario_*` labels can't leak — enforced by an AST test.

## Synthetic validation (10k, seed 42 — actual run)

| Rule | Detections | Notes |
|---|---|---|
| AUTH-001 | 61 | brute-force chains + credential_compromise_001 |
| AUTH-002 | 425 | unusual_login nights + late random logons |
| AUTH-003 | 2665 | high count is dataset noise (random source IP per event); window-relative by design |
| PROC-001 / PROC-002 | 51 / 51 | sus_process chains + credential_compromise_001 |
| NET-001 | 150 | doc-range external conns incl. credential_compromise_001 |
| NET-002 | 0 | dataset has no DNS bursts — covered by unit test |
| DATA-001 | 17 | 4 GB spikes incl. credential_compromise_001 |

`credential_compromise_001` yields AUTH-001 + PROC-001 (+PROC-002) + NET-001 + DATA-001
as **separate** detections — assembly into an incident is the correlation
engine's job. `benign_volume` (≤300 MB/event) stays under the 1 GB DATA-001
line by design. Reruns are fingerprint-identical.
