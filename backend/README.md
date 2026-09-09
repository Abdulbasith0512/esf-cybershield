# ESF CyberShield — Backend (Slice 1: event foundation)

**PostgreSQL is the system of record.** One table (`security_events`), one
ingest path, one query API. No detection, ML, graph, or RAG in this slice.

## Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | open | Liveness, no DB touch |
| POST | `/api/v1/events` | X-API-Key* | Ingest one event (201; idempotent re-POST) |
| POST | `/api/v1/events/batch` | X-API-Key* | Bounded batch, partial success |
| GET | `/api/v1/events` | open (dev) | Filter + paginate |
| GET | `/api/v1/events/{event_id}` | open (dev) | Single event by external ID |

\* Required only when `INGEST_API_KEY` is set; empty = open local dev.

## Idempotency

`event_id` is UNIQUE. Re-POSTing an existing `event_id` returns the stored
row (same `id`), never a second row. Concurrent races are resolved via the
UNIQUE constraint catch-and-reload path.

## Batch behavior

**Partial success** (deliberate): each event commits independently. A
duplicate/invalid row never rolls back good rows. Response:
`{accepted, duplicates, rejected, results: [{event_id, status, id?, error?}]}`.
Telemetry shippers retry whole batches, so atomic rollback would amplify
duplicates and lose evidence. Max size via `MAX_BATCH_SIZE` (default 500).

## Auth

Set `INGEST_API_KEY` in `.env` to require `X-API-Key` on both POST endpoints
(401 otherwise). GETs stay open for local dev; the dependency is structured
so it can be applied to reads later with a one-line change. Keys are never
logged; raw payloads are never dumped to logs.

## Install

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Requires Python 3.11+.

## Configure

```powershell
copy ..\.env.example ..\.env
```

| Var | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | `postgresql+psycopg://esf:changeme@localhost:5432/esf` | Postgres (prod) or `sqlite:///...` (offline/tests). Deployment with SQLite must use an absolute persistent path, e.g. `sqlite:////data/esf.db`; the app never creates schema at startup, so initialize a fresh database once with `alembic upgrade head` (see Migrate). |
| `INGEST_API_KEY` | empty (open) | Require X-API-Key on POST when set |
| `MAX_BATCH_SIZE` | 500 | Batch bound |
| `MAX_PAGE_SIZE` | 500 | `page_size` bound |
| `CORS_ORIGINS` | localhost:3000,5173 | Allowed origins |

Never commit `.env`.

## Migrate

```powershell
cd backend
.\.venv\Scripts\python.exe -m alembic upgrade head
.\.venv\Scripts\python.exe -m alembic downgrade -1
```

The app never migrates at startup; schema ownership stays with Alembic.
For a containerized SQLite deployment, initialize the persistent volume once
(the volume survives after the one-off container exits):

```powershell
docker compose run --rm backend alembic upgrade head
```

This uses `DATABASE_URL=sqlite:////data/esf.db` from `docker-compose.yml`.
Demo seeding is a separate one-off step below; benchmark datasets are never
used for seeding and are never copied into images.

## Demo seed (deployment)

Populate a freshly migrated database with the small synthetic demo dataset
(`data/synthetic/sample_demo.jsonl`, 200 events -> 20 detections ->
12 incidents, plus one guarded demo assignee/note on the top incident).
The backend never seeds on startup.

From a checkout (SQLite at an absolute persistent path):

```powershell
$env:DATABASE_URL = 'sqlite:////data/esf.db'
.\.venv\Scripts\python.exe scripts/seed_demo.py
```

Via Docker Compose (after `alembic upgrade head`):

```powershell
docker compose --profile seed run --rm seed
```

Requirements and guarantees:

- `models/ueba/model.joblib` (tracked, ~2 MB) must be readable; training is
  out of scope, nothing is downloaded, no network is used. Compose
  bind-mounts it read-only; the production backend image does not contain it
  (the running API never loads the model file).
- Idempotent: re-running changes nothing and reports
  `demo data already seeded / nothing to do`. Deterministic IDs come from the
  existing pipeline (event IDs, UUIDv5 detections, correlation IDs).
- Never runs migrations, drops, or deletes; fails clearly when
  `DATABASE_URL` is unset or the schema is not migrated.

## Run / Test

```powershell
cd backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --port 8000
.\.venv\Scripts\python.exe -m pytest tests/ -v
```

Interactive docs: `http://localhost:8000/docs`
