# Architecture — Slice 1: Event Foundation

**PostgreSQL is the system of record.**

## Flow

```
External telemetry
  -> POST /api/v1/events[/batch] (Pydantic validation + X-API-Key)
  -> normalize service (safe canonicalization only)
  -> security_events (PostgreSQL)
  -> GET /api/v1/events[?filters] (query API)
```

## SecurityEvent schema

Single table `security_events`:

- `id` UUID PK (server-generated)
- `event_id` TEXT UNIQUE — external idempotency key, never mutated
- `timestamp` TIMESTAMPTZ — event time, always tz-aware at the API
- `event_type`, `source` — required canonical strings
- Nullable telemetry: `host`, `user`, `source_ip`, `destination_ip`,
  `destination_port` (0–65535), `protocol`, `process_name`,
  `parent_process`, `command_line`, `file_hash`, `domain`, `url`,
  `bytes_sent`/`bytes_received` (>= 0), `status`
- `raw_event` JSONB — original telemetry, stored unmodified
- `created_at` TIMESTAMPTZ — row creation time

Normalized columns are conceptually separated from `raw_event`: every future
detection/incident must trace back to this stored evidence. No LLM makes
security decisions; no accuracy is claimed from synthetic data.

## Indexes

- `UNIQUE(event_id)` — idempotency guarantee.
- B-tree on `timestamp`, `event_type`, `host`, `user`, `source_ip`,
  `destination_ip`, `file_hash` — one per query filter (`file_hash` = IOC lookup).
- Composite `(user, timestamp)` + `(host, timestamp)` — dominant
  time-range-per-entity pattern; avoids sort, supports ordered pagination.
  No IP composites: selectivity benefit < write cost at this scale.

## Decisions (authoritative)

1. PostgreSQL is the system of record.
2. Neo4j/ChromaDB (later) are derived views, never write targets.
3. No dual writes in one request; Postgres first, projections async later.
4. `event_id` unique; duplicate ingestion is idempotent, never a second row.
5. `raw_event` preserved byte-identical; normalization never alters it.
6. No LLM security decisions; no synthetic-data accuracy claims.

## Out of scope (later slices)

Detection rules, UEBA, ML/Isolation Forest, correlation, MITRE, Neo4j,
ChromaDB, Ollama, RAG, frontend dashboard, reports.
