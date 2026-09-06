# Synthetic Data Generation (Slice 2)

> **Warning — telemetry, not attacks.** This generator emits simulated
> SECURITY TELEMETRY for local development, testing, demos, and controlled
> evaluation. It produces no malware, exploits, credential-theft tooling,
> persistence mechanisms, or destructive commands. Command lines are benign
> inventory/admin telemetry text. **Nothing here may be treated as evidence
> of real-world model performance.**

## Purpose

Drive the pipeline end-to-end with known ground truth:

```
known scenario -> events -> (later) rules -> correlation -> incident -> risk
```

## Scenarios

| # | scenario_type | Shape |
|---|---|---|
| 1 | `normal` | Business-hours enterprise background (dominates) |
| 2 | `brute_force` | 4 failed logons -> 1 success, same user/host/IP |
| 3 | `suspicious_process` | Login -> parent process -> child shell (benign inventory cmdline) -> file read |
| 4 | `unusual_login` | 2 daytime baseline logons + 1 at ~03:xx, same user |
| 5 | `suspicious_network` | Login -> DNS for `*.invalid` -> conn to TEST-NET-3 `203.0.113.200` |
| 6 | `data_spike` | 5x 50–110 MB transfers -> 1x 4 GB transfer |
| 7 | `credential_compromise` | **Primary demo** `credential_compromise_001`: 3 fails -> success -> process -> shell telemetry -> external conn -> 4 GB transfer (8 events, ordered) |
| 8 | `benign_volume` | High-volume service workload — negative example (volume != malicious) |

Default mix: normal 88%, brute_force 3%, suspicious_process/network/unusual_login 2% each, data_spike/credential_compromise/benign_volume ~1% each. Override with `--scenario-mix normal=0.8,...` (weights sum ~1.0).

## Behavioral model: user → stable primary source IP

Every identity (`user_001…`, service accounts) owns exactly one primary IP
in `10.10.10.0/24`, assigned by a seeded shuffle — deterministic per seed,
collision-free. Normal traffic (`normal`, `benign_volume`,
`suspicious_process`, `suspicious_network`, `data_spike`) always uses the
primary IP. Controlled new-IP telemetry is allocated from the disjoint
`192.168.50.0/24` range and only where semantically intended:

- `brute_force`: whole chain from one attacker IP (≠ victim primary)
- `unusual_login`: baseline on primary IP, 03:xx login on a new IP
- `credential_compromise`: whole chain on one attacker IP (≠ victim primary)

AUTH-003 is intentionally designed to detect deviations from historical
user/source-IP behavior, so on realistic data it fires (almost) only on
these intentional scenarios — e.g. 125 detections on the 10k/seed-42
dataset, all in `brute_force`/`unusual_login`/`credential_compromise`,
zero in `normal`/`benign_volume` (previously 2,665 under random-IP
assignment).

## Event schema & vocabulary

Every record is a valid Slice 1 `EventCreate`: `event_id` (UUIDv5, unique),
tz-aware `timestamp`, `event_type` in
`{authentication, process_creation, network_connection, dns_query,
file_activity, data_transfer}`, `source` in
`{windows, linux, firewall, dns, endpoint}`, plus the nullable telemetry
columns. Entities are synthetic (`user_001…`, `WIN-001…/SRV-001…`,
private/test IPs, `203.0.113.200` external, `.invalid` domains).

## Ground truth

`raw_event` carries `{generator, synthetic: true, scenario_id,
scenario_type, seed, source_metadata}`. Top-level columns are label-free.

> **ML RULE: `scenario_id`, `scenario_type`, and `synthetic` are evaluation
> labels ONLY. Future models must never use them as features.**

## CLI

```powershell
python scripts/generate_synthetic.py --events 10000 --seed 42 --output data/synthetic/events.jsonl
python scripts/generate_synthetic.py --events 500 --seed 7 --output data/synthetic/sample.csv --format csv
python scripts/generate_synthetic.py --events 200 --seed 7 --validate   # contract check
python scripts/validate_synthetic.py data/synthetic/events.jsonl
```

`--seed 42` always yields the same dataset (UUIDv5 ids, fixed anchor
2026-09-01T08:00Z + seeded offsets, 5-day normal span, seeded out-of-order
fraction for temporal-window testing). Generation writes files only — it
never inserts into PostgreSQL. To load data, POST the file to
`POST /api/v1/events/batch` in <=500-event chunks with `X-API-Key` if set.

## Limitations

Synthetic distributions do not match any real environment; detector recall on
this data says nothing about production efficacy. Timestamps anchor to Sept
2026 (no future-times unless the anchor ages — then pass an explicit flag or
regenerate). `data/synthetic/*` and `*.csv` are git-ignored; only the small
`sample_demo.*` fixtures are force-added for reviewers.
