"""Persist the full seed-42 detection set + verify incident references (dev only).

Pipeline: events.jsonl -> detect -> persist detections -> correlate ->
MITRE/risk -> UEBA attach -> persist incidents. Verifies 914 unique
detections and that every incident detection_id resolves.

Usage:
    python scripts/run_persist_detections.py data/synthetic/events.jsonl
"""

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "backend"))

import os  # noqa: E402

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
    path = REPO / (sys.argv[1] if len(sys.argv) > 1 else "data/synthetic/events.jsonl")
    db_url = os.environ.get("DATABASE_URL", "sqlite:///./esf_incidents.db")
    model_path = REPO / "models" / "ueba" / "model.joblib"
    events = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    dets = detect(events)
    det_ids = {d.detection_id for d in dets}
    print(f"{len(events)} events -> {len(dets)} detections ({len(det_ids)} unique)")

    from app.db.models.detection import Detection as DetectionRow
    from app.db.models.incident import Incident as IncidentRow
    from app.services.persist.detections import upsert_detections
    from app.services.persist.incidents import upsert_incidents

    engine = create_engine(db_url, connect_args={"check_same_thread": False}
                           if db_url.startswith("sqlite") else {})
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def count(model, col):
        db = factory()
        try:
            total = db.execute(select(func.count()).select_from(model)).scalar_one()
            uniq = db.execute(select(func.count(func.distinct(col)))).scalar_one()
            return total, uniq
        finally:
            db.close()

    db = factory()
    try:
        created, updated = upsert_detections(db, dets)
    finally:
        db.close()
    print(f"detections first persist: created={created} updated={updated}")
    db = factory()
    try:
        created2, updated2 = upsert_detections(db, dets)
    finally:
        db.close()
    total, uniq = count(DetectionRow, DetectionRow.detection_id)
    print(f"detections second persist: created={created2} updated={updated2} "
          f"rows={total} unique={uniq}")

    by_id = {e["event_id"]: e for e in events}
    incs = correlate(dets, events_by_id=by_id)
    enrs = enrich(incs, {d.detection_id: d for d in dets})
    wrapped = attach_ueba(enrs, by_id, load(model_path))
    db = factory()
    try:
        ic, iu = upsert_incidents(db, wrapped)
    finally:
        db.close()
    print(f"incidents persist: created={ic} updated={iu}")
    itotal, iuniq = count(IncidentRow, IncidentRow.incident_id)
    print(f"incident rows={itotal} unique={iuniq}")

    # Relationship check: every incident detection_id must resolve.
    db = factory()
    try:
        stored_det_ids = set(db.execute(select(DetectionRow.detection_id)).scalars().all())
        missing = set()
        for (ids,) in db.execute(select(IncidentRow.detection_ids)).all():
            missing.update(i for i in ids if i not in stored_det_ids)
    finally:
        db.close()
    print(f"unresolved incident detection references: {len(missing)}")
    ok = (total == len(dets) == uniq and itotal == len(incs) == iuniq
          and not missing and created2 == 0)
    print("IDEMPOTENT+LINKED" if ok else "MISMATCH")
    if not ok:
        sys.exit(1)


if __name__ == "__main__":
    main()
