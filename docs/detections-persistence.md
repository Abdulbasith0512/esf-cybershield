# Slice 11 — Detection and Security Signal APIs

## Flow

```
DetectionResult (deterministic engine output)
   ↓  upsert_detections (idempotent, per-row transactions)
PostgreSQL detections table  <-- system of record for reads
   ↓  GET /api/v1/detections[/{id}] (read-only, never reruns rules)
Incident investigation (expandable detection cards)
```

## Table

`detections`: `id` (Uuid PK), `detection_id` TEXT UNIQUE (engine UUIDv5,
preserved verbatim), `rule_id/rule_name/severity/confidence/reason`,
`evidence_event_ids` (sorted unique JSONB), `metadata` JSONB,
`first_seen/last_seen` naive UTC, `created_at/updated_at`. Indexes:
rule_id, severity, first_seen, last_seen, composite `(rule_id,last_seen)`.

## Idempotency

Same `detection_id` twice = one row (full overwrite, `created_at`
preserved). Race-safe via select-then-insert + IntegrityError
catch-and-reload (SQLite-compatible). Each item commits independently.

## API

- `GET /api/v1/detections` — filters (rule_id/severity/min_confidence/
  time range), `last_seen DESC, detection_id` order, lightweight rows,
  `{items,page,page_size,total,pages}` (max 500).
- `GET /api/v1/detections/{detection_id}` — full object incl. metadata;
  404 `{"detail":"detection not found"}`.
- GETs are open (same policy as event/incident reads). No MITRE or UEBA
  endpoints were added: both already ride on incident detail, and the
  simpler architecture was preferred per review.

## Frontend

Incident page fetches each detection via bounded parallel
`GET /detections/{id}` (`allSettled`; one 404 degrades to a row banner,
never a page error). Cards expand to rule name, severity, confidence,
reason verbatim, window, evidence IDs, and a "View evidence" focus into
the on-page evidence table. MITRE/UEBA sections unchanged.

## Validation (10k, seed 42 - actual run)

10,000 events -> 914 detections -> 914 rows, 0 duplicates; re-persist
stable. Every incident detection reference resolves (0 unresolved).
Credential-compromise `1125cb0a-...`: 9 detections resolve (6 distinct
rules), all evidence resolves to events, risk 100/CRITICAL and UEBA
1.0/flagged unchanged.
