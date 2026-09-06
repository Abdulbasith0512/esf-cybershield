# Incident Persistence (Slice 9)

## Flow

```
Correlation / MITRE / Risk / UEBA enrichment (in memory)
        |
        v  upsert_incidents (idempotent, per-row transactions)
PostgreSQL incidents table  <-- system of record
        |
        v  GET /api/v1/incidents[/{id}] (read-only)
Next.js incident queue + detail
```

## Table

`incidents`: `id` (Uuid PK), `incident_id` TEXT UNIQUE (deterministic
correlation ID, preserved verbatim — never regenerated), scalar queryable
columns (`title/severity/status/confidence/reason/risk_score/risk_band/
risk_explanation/first_seen/last_seen` naive UTC), JSONB lists
(`detection_ids`, `evidence_event_ids`, sorted unique) and objects
(`metadata`, `mitre_techniques`, `risk_breakdown`, `ueba_evidence`),
`created_at/updated_at`. Indexes: severity, status, risk_score, risk_band,
first_seen, last_seen, plus composite `(risk_band, last_seen)` for the
queue's dominant band-filtered recency query.

## Idempotency

Same `incident_id` twice = one row (full overwrite of derived fields,
`created_at` preserved). Race-safe via select-then-insert +
IntegrityError catch-and-reload (SQLite-compatible; no PG-only
ON CONFLICT). Each item commits independently; a bad row rolls back
only itself.

## API

- `GET /api/v1/incidents` — filters (severity/status/risk_band/
  min_risk_score/time range), `last_seen DESC, incident_id` order,
  `{items,page,page_size,total,pages}` envelope (max 500/page).
  List rows are lightweight: UEBA as flag/score only, no raw payloads.
- `GET /api/v1/incidents/{incident_id}` — full detail incl. MITRE,
  breakdown, UEBA evidence; 404 `{"detail":"incident not found"}`.
- GETs are open (same policy as event reads); errors sanitized
  (422/404/503/500, never SQL/paths).

## What persistence does NOT do

No recalculation of detection, correlation, MITRE, risk, or UEBA.
No workflow transitions (status preserved as generated; acknowledge/
investigate/resolve belong to a later slice). No dual writes.

## Validation (10k, seed 42 - actual run)

10,000 events -> 914 detections -> 689 incidents -> 689 rows,
0 duplicate IDs; re-persist stays 689. Credential-compromise
`1125cb0a-...` round-trips field-identical (risk 100/CRITICAL,
UEBA 1.0 flagged, 6 MITRE mappings) through DB and API.
