"""Persist the full seed-42 pipeline into PostgreSQL/SQLite (dev/validation only).

Pipeline: events.jsonl -> detect -> correlate -> MITRE/risk -> UEBA attach
-> idempotent upsert. Verifies 689 unique rows and idempotent re-persist.

Usage:
    python scripts/run_persist_incidents.py data/synthetic/events.jsonl
"""

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "backend"))

from sqlalchemy import create_engine, func, select  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from app.db.database import Base  # noqa: E402
from app.services.correlate.engine import correlate  # noqa: E402
from app.services.detect.engine import detect  # noqa: E402
from app.services.mitre.enrich import enrich  # noqa: E402
from app.services.ueba.attach import attach_ueba  # noqa: E402
from app.services.ueba.serialization import load  # noqa: E402

import app.db.models  # noqa: E402,F401


def main() -> None:
    import os

    path = REPO / (sys.argv[1] if len(sys.argv) > 1 else "data/synthetic/events.jsonl")
    db_url = os.environ.get("DATABASE_URL", "sqlite:///./esf_incidents.db")
    model_path = REPO / "models" / "ueba" / "model.joblib"
    events = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    by_id = {e["event_id"]: e for e in events}
    dets = detect(events)
    det_by_id = {d.detection_id: d for d in dets}
    incs = correlate(dets, events_by_id=by_id)
    enrs = enrich(incs, det_by_id)
    model = load(model_path)
    wrapped = attach_ueba(enrs, by_id, model)
    print(f"{len(events)} events -> {len(dets)} detections -> {len(incs)} incidents")

    from app.services.persist.incidents import upsert_incidents

    engine = create_engine(db_url, connect_args={"check_same_thread": False}
                           if db_url.startswith("sqlite") else {})
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    from app.db.models.incident import Incident as IncidentRow

    def persist(items):
        db = factory()
        try:
            return upsert_incidents(db, items)
        finally:
            db.close()

    created, updated = persist(wrapped)
    print(f"first persist: created={created} updated={updated}")
    db = factory()
    try:
        total = db.execute(select(func.count()).select_from(IncidentRow)).scalar_one()
        uniq = db.execute(select(func.count(func.distinct(IncidentRow.incident_id)))).scalar_one()
    finally:
        db.close()
    print(f"rows={total} unique_ids={uniq} duplicates={total - uniq}")

    created2, updated2 = persist(wrapped)
    db = factory()
    try:
        total2 = db.execute(select(func.count()).select_from(IncidentRow)).scalar_one()
    finally:
        db.close()
    print(f"second persist: created={created2} updated={updated2} rows={total2}")
    ok = total == len(wrapped) and uniq == total and total2 == total
    print("IDEMPOTENT" if ok else "MISMATCH")
    if not ok:
        sys.exit(1)


if __name__ == "__main__":
    main()
