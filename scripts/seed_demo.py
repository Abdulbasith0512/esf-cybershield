"""Seed a deployment database with the small synthetic demo dataset.

Flow (run once per fresh database, after migrations):

    alembic upgrade head
    python scripts/seed_demo.py

What it does, in order:
  1. reads data/synthetic/sample_demo.jsonl (fixed demo input, never modified)
  2. stores events idempotently (existing event_id rows are reused)
  3. runs detect -> correlate -> MITRE/risk enrich -> UEBA attach (tracked model)
  4. upserts detections + incidents idempotently (deterministic IDs)
  5. applies one guarded demo case touch (assignee + note) so case
     management has content; skipped when already applied. Status is left
     alone: upsert_incidents re-derives it from the pipeline on every
     persist, so a seeded status could never be stable.

The script never runs migrations (it fails clearly when schema is missing),
never drops/deletes anything, and performs no
network I/O. Re-running against the same database changes nothing and
 reports "already seeded / nothing to do". Public evaluation datasets are
 never referenced.

Configuration (environment, never hardcoded paths):
  DATABASE_URL    required, e.g. sqlite:////data/esf.db
  SEED_DATA_FILE  optional override, default <repo>/data/synthetic/sample_demo.jsonl
  SEED_MODEL_FILE optional override, default <repo>/models/ueba/model.joblib
"""

import json
import os
import sys
from pathlib import Path

SEED_DIR = Path(__file__).resolve().parent
REPO = SEED_DIR.parent
BACKEND_DIR = Path(os.environ.get("SEED_BACKEND_DIR", str(REPO / "backend")))
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from sqlalchemy import create_engine, desc, func, select  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

DATA_FILE = Path(os.environ.get(
    "SEED_DATA_FILE", str(REPO / "data" / "synthetic" / "sample_demo.jsonl")))
MODEL_FILE = Path(os.environ.get(
    "SEED_MODEL_FILE", str(REPO / "models" / "ueba" / "model.joblib")))

REQUIRED_TABLES = frozenset({
    "security_events", "detections", "incidents",
    "incident_notes", "incident_activity",
})

DEMO_ASSIGNEE = "demo-analyst"
DEMO_ACTOR = "seed-demo"
DEMO_NOTE_BODY = (
    "Demo triage note (seeded): review the detection timeline and validate "
    "whether the observed activity is expected in this environment."
)


def _fail(message: str) -> int:
    print(f"seed_demo: error: {message}", file=sys.stderr)
    return 2


def _resolve_database() -> tuple[str, Path | None]:
    db_url = (os.environ.get("DATABASE_URL") or "").strip()
    if not db_url:
        return "", None
    if db_url.startswith("sqlite:"):
        from sqlalchemy.engine import make_url

        database = make_url(db_url).database or ""
        if database == ":memory:":
            return db_url, None
        candidate = Path(database)
        if not candidate.is_absolute():
            return db_url, None
        return db_url, candidate
    return db_url, None


def main() -> int:
    db_url, sqlite_path = _resolve_database()
    if not db_url:
        return _fail("DATABASE_URL is not set; refusing to guess a location. "
                      "Set it explicitly, e.g. DATABASE_URL=sqlite:////data/esf.db")
    if db_url.startswith("sqlite:") and sqlite_path is None:
        return _fail(f"refusing SQLite URL {db_url!r}: use an absolute file path "
                      "(e.g. sqlite:////data/esf.db), never :memory: or a relative path")
    if sqlite_path is not None and not sqlite_path.parent.exists():
        return _fail(f"database directory does not exist: {sqlite_path.parent} "
                      "(mount the persistent volume first)")
    if not DATA_FILE.exists():
        return _fail(f"demo dataset not found: {DATA_FILE}")
    if not MODEL_FILE.exists():
        return _fail(f"UEBA model not found: {MODEL_FILE} "
                      "(tracked at models/ueba/model.joblib; training is out of scope)")

    from app.db.database import Base  # noqa: E402,F401 -- metadata anchor; schema itself is asserted, never created here
    from app.db.models.detection import Detection as DetectionRow  # noqa: E402
    from app.db.models.incident import Incident as IncidentRow  # noqa: E402
    from app.db.models.security_event import SecurityEvent as SecurityEventRow  # noqa: E402
    from app.services.correlate.engine import correlate  # noqa: E402
    from app.services.detect.engine import detect  # noqa: E402
    from app.schemas.events import EventCreate  # noqa: E402
    from app.services.ingest import store_event  # noqa: E402
    from app.services.mitre.enrich import enrich  # noqa: E402
    from app.services.persist import cases as case_store  # noqa: E402
    from app.services.persist.detections import upsert_detections  # noqa: E402
    from app.services.persist.incidents import upsert_incidents  # noqa: E402
    from app.services.ueba.attach import attach_ueba  # noqa: E402
    from app.services.ueba.serialization import load as load_model  # noqa: E402

    import app.db.models  # noqa: E402,F401

    engine = create_engine(db_url, connect_args={"check_same_thread": False}
                           if db_url.startswith("sqlite") else {})
    from sqlalchemy import inspect as sa_inspect

    present = set(sa_inspect(engine).get_table_names())
    if not REQUIRED_TABLES <= present:
        return _fail("schema not initialized (missing: "
                      f"{sorted(REQUIRED_TABLES - present)}); run alembic upgrade head first")
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    events = [json.loads(line) for line in DATA_FILE.read_text(encoding="utf-8").splitlines()
              if line.strip()]
    if not events:
        return _fail(f"demo dataset is empty: {DATA_FILE}")

    db = factory()
    try:
        new_events = 0
        for event in events:
            validated = EventCreate(**event).model_dump()
            _row, deduped = store_event(db, validated)
            new_events += 0 if deduped else 1
    finally:
        db.close()

    dets = detect(events)
    db = factory()
    try:
        det_created, det_updated = upsert_detections(db, dets)
    finally:
        db.close()

    by_id = {e["event_id"]: e for e in events}
    incidents = correlate(dets, events_by_id=by_id)
    enriched = enrich(incidents, {d.detection_id: d for d in dets})
    wrapped = attach_ueba(enriched, by_id, load_model(MODEL_FILE))
    db = factory()
    try:
        inc_created, inc_updated = upsert_incidents(db, wrapped)
    finally:
        db.close()

    case_touched = False
    db = factory()
    try:
        top = db.execute(select(IncidentRow).order_by(
            desc(IncidentRow.risk_score), IncidentRow.incident_id)).scalars().first()
        if top is not None:
            # Guarded and stable: assignee/notes are case-layer-owned and are
            # never overwritten by upsert_incidents, so these apply exactly once.
            # Status is intentionally untouched (upsert re-derives it every run;
            # seeding one would append a duplicate STATUS_CHANGED per re-seed).
            db.refresh(top)
            if top.assignee is None:
                case_store.update_case(db, top.incident_id,
                                       assignee=DEMO_ASSIGNEE, actor=DEMO_ACTOR)
                case_touched = True
            if not case_store.list_notes(db, top.incident_id):
                case_store.add_note(db, top.incident_id,
                                    body=DEMO_NOTE_BODY, author=DEMO_ACTOR)
                case_touched = True
        event_total = db.execute(
            select(func.count()).select_from(SecurityEventRow)).scalar_one()
        det_total = db.execute(
            select(func.count()).select_from(DetectionRow)).scalar_one()
        inc_total = db.execute(
            select(func.count()).select_from(IncidentRow)).scalar_one()
    finally:
        db.close()

    print(f"events: {event_total} (new={new_events})")
    print(f"detections: {det_total} (created={det_created} updated={det_updated})")
    print(f"incidents: {inc_total} (created={inc_created} updated={inc_updated})")
    # Re-persisting identical content reports updates but changes nothing;
    # only brand-new rows or a first-time case touch count as changes.
    if not (new_events or det_created or inc_created or case_touched):
        print("demo data already seeded / nothing to do")
    print("status: success")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
