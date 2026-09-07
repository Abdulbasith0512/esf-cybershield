"""Controlled CSE-CIC-IDS2018 ingestion through the existing event path.

Flow: CSV -> CseCicIds2018Adapter -> EventCreate validation -> store_event
(normalize + idempotent insert). Dry-run by default; writes to the database
ONLY with --persist. Streams rows in bounded batches; never loads the file.

Production database is PostgreSQL via DATABASE_URL. PostgreSQL is not
reachable in every dev environment; when DATABASE_URL is unset the script
uses a local SQLite file through the identical store_event code path.
For real PostgreSQL: docker compose up -d postgres, then set DATABASE_URL.

Usage:
    python scripts/ingest_cse_cic_ids2018.py --input data/public/cse_cic_ids2018/raw/02-14-2018.csv --limit 10000
    python scripts/ingest_cse_cic_ids2018.py --input data/public/cse_cic_ids2018/raw/02-14-2018.csv --limit 10000 --persist
"""

import argparse
import os
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "backend"))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Dry-run or controlled-persist CSE-CIC-IDS2018 flows via store_event.")
    parser.add_argument("--input", required=True, help="Path to a source CSV file.")
    parser.add_argument("--limit", type=int, default=10000, help="Maximum rows to read.")
    parser.add_argument("--batch-size", type=int, default=500,
                        help="Rows per commit batch (<= max_batch_size).")
    parser.add_argument("--database-url", default=None,
                        help="Database URL (default: $DATABASE_URL else local SQLite file).")
    parser.add_argument("--source-file", default=None,
                        help="Identity override (default: input basename).")
    parser.add_argument("--persist", action="store_true",
                        help="Write to the database. Without it: dry-run only.")
    return parser


def main() -> None:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.core.config import get_settings
    from app.db.database import Base
    from app.schemas.events import EventCreate
    from app.services.datasets.cse_cic_ids2018 import CseCicIds2018Adapter
    from app.services.ingest import store_event

    import app.db.models  # noqa: F401

    args = build_parser().parse_args()
    if args.limit is not None and args.limit < 1:
        print("ERROR: --limit must be >= 1", file=sys.stderr)
        sys.exit(2)
    if args.batch_size < 1 or args.batch_size > get_settings().max_batch_size:
        print(f"ERROR: --batch-size must be 1..{get_settings().max_batch_size}", file=sys.stderr)
        sys.exit(2)
    input_path = Path(args.input)
    if not input_path.is_file():
        print(f"ERROR: input is not a file: {input_path}", file=sys.stderr)
        sys.exit(2)

    source_file = args.source_file or input_path.name
    adapter = CseCicIds2018Adapter()
    read = rejected = validated = 0
    reasons: Counter[str] = Counter()
    pending: list[dict] = []

    db_url = args.database_url or os.environ.get("DATABASE_URL")
    factory = None
    if args.persist:
        if not db_url:
            db_file = REPO / "data" / "public" / "cse_cic_ids2018" / "import.sqlite3"
            db_url = f"sqlite:///{db_file}"
            print(f"NOTE: no DATABASE_URL; using local SQLite file: {db_file}")
            print("      For PostgreSQL: docker compose up -d postgres and set DATABASE_URL.")
        engine = create_engine(db_url, connect_args={"check_same_thread": False}
                               if db_url.startswith("sqlite") else {})
        Base.metadata.create_all(engine)
        factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    accepted = duplicates = 0

    def flush() -> None:
        nonlocal accepted, duplicates
        assert factory is not None
        db = factory()
        try:
            for payload in pending:
                _, deduped = store_event(db, payload)
                if deduped:
                    duplicates += 1
                else:
                    accepted += 1
        finally:
            db.close()
            pending.clear()

    for source_row, raw in adapter.iter_rows(input_path, limit=args.limit):
        read += 1
        result = adapter.normalize_row(raw, source_file=source_file, source_row=source_row)
        if not result.ok or result.event is None:
            rejected += 1
            reasons[result.rejected.code if result.rejected else "unknown"] += 1
            continue
        try:
            pending.append(EventCreate(**result.event).model_dump())
        except Exception as exc:  # noqa: BLE001 -- per-row contract failure
            rejected += 1
            reasons[f"contract:{type(exc).__name__}"] += 1
            continue
        validated += 1
        if args.persist and len(pending) >= args.batch_size:
            flush()
    if args.persist and pending:
        flush()

    mode = "PERSIST" if args.persist else "DRY-RUN (no writes)"
    print(f"mode: {mode}")
    print(f"rows read: {read}")
    print(f"rows normalized: {validated}")
    print(f"rows rejected: {rejected}")
    print(f"rejection reasons: {dict(reasons) or 'none'}")
    if args.persist:
        print(f"persisted: {accepted} duplicates: {duplicates}")


if __name__ == "__main__":
    main()
