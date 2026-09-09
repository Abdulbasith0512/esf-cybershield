"""Provider abstraction and the deterministic local-test provider.

Only (observable type, normalized value) is handed to a provider — never raw
events, labels, or incident context. The local provider reads a static fixture
catalog of RFC-reserved test indicators; it performs no network I/O and makes
no real-world threat claims.
"""

import json
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path

from app.services.threatintel.models import Observable, ThreatIntelResult

LOCAL_TEST_PROVIDER = "local-test"


class ThreatIntelError(RuntimeError):
    """A provider failed. Enrichment converts this to unavailable, never 500."""


class ThreatIntelProvider(ABC):
    """Provider contract. Implementations must be side-effect free w.r.t.
    stored data and must never raise for an unknown observable — unknown is
    a classification, not an error."""

    name: str = "base"

    @abstractmethod
    def lookup(self, observable: Observable) -> ThreatIntelResult:
        """Return structured intelligence for one normalized observable."""
        raise NotImplementedError


def _load_catalog() -> dict:
    path = Path(__file__).parent / "catalog.json"
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


class LocalThreatIntelProvider(ThreatIntelProvider):
    """Fixture intelligence for development/testing. NOT real threat data.

    Every entry uses RFC-reserved documentation/test values (TEST-NET-1/2/3,
    .invalid/.example, well-known test vectors) so fixtures can never be
    mistaken for real-world indicators.
    """

    name = LOCAL_TEST_PROVIDER

    def __init__(self) -> None:
        catalog = _load_catalog()
        self.version = str(catalog.get("catalog_version", "local-test-v1"))
        self._entries: dict[tuple[str, str], dict] = {}
        for entry in catalog.get("entries", []):
            self._entries[(entry["type"], entry["value"])] = entry

    def lookup(self, observable: Observable) -> ThreatIntelResult:
        entry = self._entries.get((observable.type, observable.normalized_value))
        now = datetime.now(timezone.utc)
        if entry is None:
            return ThreatIntelResult(
                provider=self.name, observable_type=observable.type,
                observable_value=observable.normalized_value,
                classification="unknown", confidence=0.0,
                categories=["not-in-fixture"], retrieved_at=now,
                metadata={"catalog_version": self.version, "fixture": True},
            )
        return ThreatIntelResult(
            provider=self.name, observable_type=observable.type,
            observable_value=observable.normalized_value,
            classification=entry["classification"], confidence=float(entry["confidence"]),
            categories=list(entry.get("categories", [])),
            first_seen=entry.get("first_seen"), last_seen=entry.get("last_seen"),
            reference=entry.get("reference"), retrieved_at=now,
            metadata={"catalog_version": self.version, "fixture": True,
                      "note": entry.get("note", "")},
        )


def provider_registry() -> dict[str, ThreatIntelProvider]:
    """All configured providers. Only local-test ships in this slice; future
    external providers register here behind settings + credentials."""
    local = LocalThreatIntelProvider()
    return {local.name: local}
