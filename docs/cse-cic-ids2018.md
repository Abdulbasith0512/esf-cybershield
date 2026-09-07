# Slice 12A — CSE-CIC-IDS2018 public dataset adapter
# Official reference: https://www.unb.ca/cic/datasets/ids-2018.html
# (Canadian Institute for Cybersecurity, University of New Brunswick)

## Purpose

Convert CSE-CIC-IDS2018 network-flow CSV rows into the existing canonical
`SecurityEvent` (`EventCreate`) representation **without inventing missing
telemetry**. This slice is normalization and inspection only: no database
ingestion, no detection, no incidents.

> This adapter does not claim attack-detection accuracy. The processed CSVs
> are network-flow telemetry, not complete host/authentication telemetry.
> Existing rules that require user/host/auth fields will simply not fire on
> flow-only records, which is correct behavior rather than a defect.

## Downloaded structure

```
data/public/cse_cic_ids2018/raw/
    02-14-2018.csv   02-15-2018.csv   02-16-2018.csv
    02-20-2018.csv   02-21-2018.csv   02-22-2018.csv
    02-23-2018.csv   02-28-2018.csv
    03-01-2018.csv   03-02-2018.csv
```

The raw CSVs are git-ignored (`*.csv` plus an explicit
`data/public/cse_cic_ids2018/raw/*` rule) and never committed.

## Observed schema

- 80 columns in 9 of 10 files: 79 CICFlowMeter features plus `Label`.
- `02-20-2018.csv` carries 84 columns, additionally exposing `Src IP`,
  `Src Port`, and `Dst IP`.
- Only `Dst Port` is present in every file; no file exposes `user`/`host`.
- Timestamp format: `%d/%m/%Y %H:%M:%S` (e.g. `14/02/2018 08:31:01`).
  Capture timestamps carry no zone information; the adapter interprets them
  as UTC and documents that assumption here. Timestamps are **not globally
  ordered** in the source files.
- Observed `02-14-2018` labels: Benign 667,626; FTP-BruteForce 193,360;
  SSH-Bruteforce 187,589.

## Flow-only vs endpoint-aware capability

The same adapter handles both shapes by inspecting each file's header:

- **Flow-only** (9 files): `source_ip`, `destination_ip`, `user`, `host`
  remain null. No placeholder IPs, no hashed users, no row-number hosts.
- **Endpoint-aware** (`02-20-2018.csv`): `Src IP`/`Dst IP` map when valid
  per `ipaddress`; `Src Port` has no canonical field and stays inside
  `raw_event.flow`. Invalid IPs become null, never fabricated.

## Canonical mapping

| CSV column(s) | EventCreate field | Rule |
|---|---|---|
| (identity) | `event_id` | UUIDv5 over dataset + adapter version + source file + 1-based source row; order-independent |
| Timestamp | `timestamp` | strict `%d/%m/%Y %H:%M:%S`, tz-aware UTC; unparseable → reject `bad_timestamp` |
| — | `event_type` | always `network_connection` (describes telemetry, never the Label) |
| — | `source` | always `cse_cic_ids2018` |
| Dst Port | `destination_port` | int 0–65535; otherwise reject `bad_port` |
| Protocol | `protocol` | 6→TCP, 17→UDP, 1→ICMP, else raw text |
| TotLen Fwd/Bwd Pkts | `bytes_sent`/`bytes_received` | non-negative ints; unparseable/negative → null |
| Label | `raw_event.evaluation_only` | `{label, evaluation: true}` — evaluation metadata only |
| all other columns | `raw_event.flow` | original header names, numbers preserved (int/float/text) |
| provenance | `raw_event` | `{dataset, dataset_source, source_file, adapter_version}` |
| — | `host/user/status/...` | null unless genuinely present |

## Label policy (evaluation-only)

The dataset Label is preserved verbatim under
`raw_event.evaluation_only.label` and nowhere else. It never determines
`event_type`, severity, risk, correlation, UEBA features, thresholds, or
model selection. Renaming the Label column value leaves every top-level
field byte-identical (tested). Static checks assert the adapter package
contains no `scenario_id`/`scenario_type`/`synthetic`/`seed` references.

## Event ID strategy

`uuid5(NAMESPACE, dataset|adapter_version|source_file|source_row)` where
`source_row` is the 1-based data-row index captured at CSV read time,
before any sorting, filtering, or batching. Every valid source row is
therefore preserved as a distinct event, even when two rows share every
observable flow field. Processing order never affects IDs as long as the
original row number travels with the row; repeating the adapter over the
same file reproduces identical IDs. Including the adapter version means a
future adapter change cleanly re-keys identities instead of silently
reusing them. This is consistent with the existing idempotent-ingestion
semantics: re-ingesting the same file can never create duplicates.

## Usage

```powershell
python scripts/inspect_cse_cic_ids2018.py --input data/public/cse_cic_ids2018/raw/02-14-2018.csv --limit 10000
python backend/.venv/Scripts/python.exe -m pytest backend/tests/test_cse_cic_ids2018.py -q
```

## Slice 12B — controlled ingestion

```powershell
python scripts/ingest_cse_cic_ids2018.py --input data/public/cse_cic_ids2018/raw/02-14-2018.csv --limit 10000
python scripts/ingest_cse_cic_ids2018.py --input data/public/cse_cic_ids2018/raw/02-14-2018.csv --limit 10000 --persist
```

Without `--persist` the script is dry-run only (zero writes). With `--persist`
it validates every record against `EventCreate` and stores it through the
existing `store_event` path in bounded batches (default 500, honoring
`max_batch_size`). Repeating the same command only produces duplicates —
never new rows. Production target is PostgreSQL via `DATABASE_URL`
(`docker compose up -d postgres`); without it the script uses a local
SQLite file through the identical code path.

Dataset-scoped evaluation reads rows back with
`WHERE source = 'cse_cic_ids2018'`, re-attaches UTC, and runs the existing
`detect → correlate → enrich → UEBA attach` chain on that subset only.
Expected on flow-only samples: near-zero detections (only `NET-001` on IOC
matches and `DATA-001` past 1 GB can fire) and UEBA `unavailable`
(user is null) — a limitation of flow telemetry, not a pipeline defect.

## Known limitations

- UTC interpretation of zone-less capture timestamps is an assumption.
- No user/host/authentication telemetry exists in these files; rules
  requiring those fields will not fire on adapted records.
- `02-20-2018.csv` (4 GB) should be inspected with small `--limit` values.
- Every valid source row becomes a distinct event, even with identical flow
  fields; dedupe happens only on exact (file, row) re-ingestion.
