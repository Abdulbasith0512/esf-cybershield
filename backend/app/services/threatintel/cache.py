"""In-memory enrichment cache. Read-through, TTL-bounded, no new tables.

Rationale: UEBA and MITRE enrichment are already read-through services with
no dedicated persistence; a threat-intel result cache follows the same
architecture. Once a real (network) provider ships, this cache is what
prevents duplicate external lookups for the same observable/provider pair.
Process-local duplication across workers is acceptable: lookups stay correct,
only repeated once per worker per TTL window.
"""

from datetime import datetime, timedelta, timezone

from app.services.threatintel.models import ThreatIntelResult


class ThreatIntelCache:
    """Key (provider, observable type, normalized value) -> cached result."""

    def __init__(self, ttl_seconds: int = 3600) -> None:
        self.ttl_seconds = max(int(ttl_seconds), 0)
        self._store: dict[tuple[str, str, str], tuple[ThreatIntelResult, datetime]] = {}

    def _now(self) -> datetime:
        return datetime.now(timezone.utc)

    def get(self, provider: str, observable_type: str,
            normalized_value: str) -> ThreatIntelResult | None:
        slot = self._store.get((provider, observable_type, normalized_value))
        if slot is None:
            return None
        result, expires_at = slot
        if self._now() >= expires_at:
            self._store.pop((provider, observable_type, normalized_value), None)
            return None
        return result

    def put(self, result: ThreatIntelResult) -> None:
        expires_at = self._now() + timedelta(seconds=self.ttl_seconds)
        self._store[(result.provider, result.observable_type,
                     result.observable_value)] = (result, expires_at)

    def __len__(self) -> int:
        return len(self._store)
