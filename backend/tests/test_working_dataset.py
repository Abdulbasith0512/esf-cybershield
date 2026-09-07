"""Working-dataset integrity: the fixed 1M-row 02-20 subset.

Skipped automatically when the working file is absent (e.g. fresh clones
without the dataset). Streaming only; never loads the file into memory.
"""

import hashlib
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SRC = REPO / "data" / "public" / "cse_cic_ids2018" / "raw" / "02-20-2018.csv"
WORKING = REPO / "data" / "public" / "cse_cic_ids2018" / "working" / "02-20-2018-1m.csv"
EXPECTED_ROWS = 1_000_000
EXPECTED_SHA256 = "5669cfe2b1704fa35846ef527f5a3c504802bd7fb8ab1d6b8970c3e02b774bcb"

pytestmark = pytest.mark.skipif(
    not WORKING.is_file(),
    reason="working 1M dataset not present",
)


def test_header_equal():
    with SRC.open("r", encoding="utf-8-sig") as f:
        src_header = f.readline()
    with WORKING.open("r", encoding="utf-8") as f:
        dst_header = f.readline()
    assert src_header == dst_header


def test_exact_row_count():
    count = 0
    with WORKING.open("r", encoding="utf-8") as f:
        next(f)  # header
        for _ in f:
            count += 1
    assert count == EXPECTED_ROWS


def test_boundary_rows():
    with SRC.open("r", encoding="utf-8-sig") as f:
        next(f)  # header
        src_first = f.readline()  # source row 1
        src_last = None
        # After the two reads above, the next line is source row 2.
        for i, line in enumerate(f, start=2):
            if i == EXPECTED_ROWS:
                src_last = line
                break
    with WORKING.open("r", encoding="utf-8") as f:
        next(f)
        dst_first = f.readline()
    dst_last: str | None = None
    with WORKING.open("r", encoding="utf-8") as f:
        for line in f:
            dst_last = line
    assert dst_first == src_first
    assert dst_last == src_last


def test_reproducibility_hash():
    digest = hashlib.sha256()
    with WORKING.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    assert digest.hexdigest() == EXPECTED_SHA256
