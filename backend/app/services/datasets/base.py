"""Shared adapter abstractions: errors, results, and the adapter protocol."""

import csv
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Mapping, Protocol


@dataclass(frozen=True)
class RejectReason:
    """Why a single source row was not normalized. Machine-readable code."""

    code: str
    detail: str = ""


@dataclass(frozen=True)
class NormalizeResult:
    """Outcome for one source row: either an event dict or a rejection."""

    event: dict[str, Any] | None = None
    rejected: RejectReason | None = None
    flow_metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.event is not None


class AdapterError(Exception):
    """Fatal adapter failure (unreadable file, unknown schema). Not per-row."""


class DatasetAdapter(Protocol):
    """A stateless, deterministic row normalizer for one public dataset."""

    name: str
    version: str

    def normalize_row(
        self,
        row: Mapping[str, Any],
        *,
        source_file: str,
        source_row: int,
    ) -> NormalizeResult:
        """Normalize one source row to an EventCreate-compatible dict."""
        ...

    def iter_rows(self, path: str | Path, *, limit: int | None = None) -> Iterator[tuple[int, dict[str, str]]]:
        """Stream (source_row, row) pairs. source_row is the 1-based data-row
        index, captured at read time before any reordering downstream."""
        ...


def stream_csv_rows(path: str | Path, *, limit: int | None = None) -> Iterator[dict[str, str]]:
    """Yield raw CSV rows as string dicts, bounded by limit. Read-only."""
    resolved = Path(path)
    if not resolved.is_file():
        raise AdapterError(f"input is not a file: {resolved}")
    with resolved.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise AdapterError(f"CSV has no header row: {resolved}")
        count = 0
        for row in reader:
            if limit is not None and count >= limit:
                break
            count += 1
            yield {k: (v if v is not None else "") for k, v in row.items() if k is not None}
