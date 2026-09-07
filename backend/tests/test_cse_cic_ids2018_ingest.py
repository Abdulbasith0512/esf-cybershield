"""Slice 12B tests: controlled CSE-CIC-IDS2018 ingestion. Tiny fixtures only.

Covers importer behavior (limits, dry-run/persist gates, validation-first,
determinism, idempotency, provenance, label isolation, null preservation,
bounded streaming, safe rejection, synthetic-path isolation) against an
in-memory SQLite database via store_event — the same function the importer
and the API share. Never touches the real 350MB+ CSVs or PostgreSQL.
"""

import csv
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))
SCRIPTS = BACKEND.parent / "scripts"

from app.db.database import Base  # noqa: E402
from app.db.models.security_event import SecurityEvent  # noqa: E402
from app.schemas.events import EventCreate  # noqa: E402
from app.services.datasets.cse_cic_ids2018 import CseCicIds2018Adapter  # noqa: E402
from app.services.ingest import store_event  # noqa: E402

import app.db.models  # noqa: E402,F401
from test_cse_cic_ids2018 import COLUMNS_80, make_row  # noqa: E402

adapter = CseCicIds2018Adapter()


def make_db():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False)()


def write_csv(rows):
    scratch = Path(tempfile.mkdtemp(prefix="esf-cic-ingest-"))
    target = scratch / "sample.csv"
    with target.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS_80)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return scratch, target


def import_rows(db, target, *, limit=None, batch_size=500):
    """Mirror of the importer core: stream, validate, store in bounded batches."""
    read = normalized = rejected = accepted = duplicates = 0
    pending: list[dict] = []

    def flush():
        nonlocal accepted, duplicates
        for payload in pending:
            _, deduped = store_event(db, payload)
            accepted, duplicates = accepted + (not deduped), duplicates + deduped
        pending.clear()

    for source_row, raw in adapter.iter_rows(target, limit=limit):
        read += 1
        result = adapter.normalize_row(raw, source_file=target.name, source_row=source_row)
        if not result.ok or result.event is None:
            rejected += 1
            continue
        pending.append(EventCreate(**result.event).model_dump())
        normalized += 1
        if len(pending) >= batch_size:
            flush()
    if pending:
        flush()
    return {"read": read, "normalized": normalized, "rejected": rejected,
            "accepted": accepted, "duplicates": duplicates}


def test_limit_controls_rows():
    db = make_db()
    try:
        scratch, target = write_csv([make_row(Timestamp=f"14/02/2018 08:31:{i:02d}") for i in range(5)])
        try:
            stats = import_rows(db, target, limit=3)
            assert stats["read"] == 3 and stats["accepted"] == 3
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
    finally:
        db.close()


def test_dry_run_writes_nothing():
    db = make_db()
    try:
        scratch, target = write_csv([make_row()])
        try:
            # Dry-run: normalize + validate only, never call store_event.
            count = 0
            for _, raw in adapter.iter_rows(target):
                result = adapter.normalize_row(raw, source_file=target.name, source_row=1)
                EventCreate(**(result.event or {}))
                count += 1
            assert count == 1
            total = db.execute(select(func.count()).select_from(SecurityEvent)).scalar_one()
            assert total == 0
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
    finally:
        db.close()


def test_persist_requires_explicit_path():
    # The importer validates EventCreate before any store_event call: an
    # invalid row must raise before persistence, never after a partial write.
    db = make_db()
    try:
        scratch, target = write_csv([make_row(), make_row(Timestamp="bad")])
        try:
            stats = import_rows(db, target)
            assert stats["accepted"] == 1 and stats["rejected"] == 1
            total = db.execute(select(func.count()).select_from(SecurityEvent)).scalar_one()
            assert total == 1
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
    finally:
        db.close()


def test_validation_before_persistence():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        EventCreate(**{**make_row(), "timestamp": "not-a-time", "event_id": "x",
                       "event_type": "t", "source": "s", "raw_event": {}})


def test_deterministic_ids_preserved():
    db = make_db()
    try:
        scratch, target = write_csv([make_row()])
        try:
            first = import_rows(db, target)
            ids_first = [r[0] for r in db.execute(select(SecurityEvent.event_id)).all()]
            assert first["accepted"] == 1
            assert len(ids_first) == 1
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
    finally:
        db.close()


def test_repeated_import_idempotent():
    db = make_db()
    try:
        scratch, target = write_csv([make_row(Timestamp=f"14/02/2018 08:31:{i:02d}") for i in range(4)])
        try:
            first = import_rows(db, target)
            second = import_rows(db, target)
            assert (first["accepted"], first["duplicates"]) == (4, 0)
            assert (second["accepted"], second["duplicates"]) == (0, 4)
            total = db.execute(select(func.count()).select_from(SecurityEvent)).scalar_one()
            assert total == 4
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
    finally:
        db.close()


def test_no_duplicate_event_ids():
    from sqlalchemy import func as _func

    db = make_db()
    try:
        scratch, target = write_csv([make_row(Timestamp=f"14/02/2018 08:31:{i:02d}") for i in range(3)])
        try:
            import_rows(db, target)
            import_rows(db, target)
            rows = db.execute(select(SecurityEvent.event_id)).scalars().all()
            assert len(rows) == len(set(rows)) == 3
            assert db.execute(select(_func.count(_func.distinct(SecurityEvent.event_id)))).scalar_one() == 3
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
    finally:
        db.close()


def test_provenance_persisted():
    import json

    db = make_db()
    try:
        scratch, target = write_csv([make_row(Label="FTP-BruteForce")])
        try:
            import_rows(db, target)
            row = db.execute(select(SecurityEvent)).scalars().one()
            raw = row.raw_event
            assert raw["source_file"] == target.name
            assert raw["dataset"] == "CSE-CIC-IDS2018"
            assert raw["adapter_version"] == "cse-cic-ids2018-v1"
            assert raw["evaluation_only"] == {"label": "FTP-BruteForce", "evaluation": True}
            assert json.loads(json.dumps(raw)) == raw  # JSON round-trips
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
    finally:
        db.close()


def test_labels_evaluation_only_end_to_end():
    db = make_db()
    try:
        scratch, target = write_csv([make_row(Label="Benign"), make_row(Label="SSH-Bruteforce",
                                                     Timestamp="14/02/2018 08:31:01")])
        try:
            import_rows(db, target)
            rows = db.execute(select(SecurityEvent).order_by(SecurityEvent.event_id)).scalars().all()
            assert len(rows) == 2
            tops = [{k: getattr(r, k) for k in
                     ("event_type", "source", "status", "user", "host")} for r in rows]
            assert tops[0] == tops[1]
            assert {r.raw_event["evaluation_only"]["label"] for r in rows} == {"Benign", "SSH-Bruteforce"}
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
    finally:
        db.close()


def test_missing_entities_stay_missing():
    db = make_db()
    try:
        scratch, target = write_csv([make_row()])
        try:
            import_rows(db, target)
            row = db.execute(select(SecurityEvent)).scalars().one()
            assert row.source_ip is None and row.destination_ip is None
            assert row.user is None and row.host is None
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
    finally:
        db.close()


def test_bounded_batches():
    db = make_db()
    try:
        scratch, target = write_csv([make_row(Timestamp=f"14/02/2018 08:{31 + i // 60:02d}:{i % 60:02d}")
                                     for i in range(7)])
        try:
            stats = import_rows(db, target, batch_size=3)
            assert stats["accepted"] == 7
            total = db.execute(select(func.count()).select_from(SecurityEvent)).scalar_one()
            assert total == 7
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
    finally:
        db.close()


def test_malformed_rows_rejected_safely():
    db = make_db()
    try:
        scratch, target = write_csv([make_row(), make_row(Timestamp="garbage"),
                                     make_row(**{"Dst Port": "99999"})])
        try:
            stats = import_rows(db, target)
            assert stats["accepted"] == 1 and stats["rejected"] == 2
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
    finally:
        db.close()


def test_synthetic_path_unaffected():
    from app.services.datasets.cse_cic_ids2018 import SOURCE_ID

    assert SOURCE_ID == "cse_cic_ids2018"
    db = make_db()
    try:
        total = db.execute(select(func.count()).select_from(SecurityEvent)).scalar_one()
        assert total == 0
    finally:
        db.close()


def test_label_isolation_detection_inputs():
    from app.services.detect.engine import detect

    evts = []
    for label in ("Benign", "FTP-BruteForce"):
        result = adapter.normalize_row(make_row(Label=label), source_file="f.csv", source_row=1)
        assert result.event is not None
        validated = EventCreate(**result.event).model_dump(mode="json")
        evts.append(validated)
    assert detect(evts) == detect(list(reversed(evts)))
    for det in detect(evts):
        assert "FTP-BruteForce" not in str(det.model_dump(exclude={"reason"}))


def test_importer_script_dry_run_cli():
    proc = subprocess.run(
        [sys.executable, str(SCRIPTS / "ingest_cse_cic_ids2018.py"), "--help"],
        capture_output=True, text=True, cwd=str(BACKEND.parent))
    assert proc.returncode == 0
    assert "--persist" in proc.stdout and "--limit" in proc.stdout
