# Threat Intelligence / IOC Enrichment (Slice 40)

Architecture + local deterministic enrichment. No external provider, no API
keys, no network access. Enrichment is advisory context only.

> The `local-test` provider is NOT real threat intelligence. It matches a
> static fixture catalog of RFC-reserved test indicators to prove the
> architecture, API, and UI behavior. Never treat its output as a verdict
> about real-world infrastructure.

## 1. IOC model

`backend/app/services/threatintel/models.py`:

- `Observable`: `type`, `value` (original), `normalized_value`, `source`
  (`source_ip` | `destination_ip` | `domain` | `url` | `file_hash`),
  `first_seen` / `last_seen` (incident-window bounds), `event_count` (total),
  `event_ids` (bounded sorted sample, max 25).
- `ThreatIntelResult`: `provider`, observable identity, `classification`
  (`benign` | `suspicious` | `malicious` | `unknown`), `confidence` 0–1,
  `categories`, optional `first_seen` / `last_seen` / `reference`,
  `retrieved_at`, and a small `metadata` map. Arbitrary provider payloads
  are never exposed; the frontend only sees this struct.
- `EnrichedObservable`: observable + `available` flag + result-or-`error` +
  `detection_ids` + `incident_id` traceability.

## 2. Supported observable types

| Type | Source column | Status |
|---|---|---|
| `ipv4` / `ipv6` | `source_ip`, `destination_ip` | Fully supported; flow datasets emit these. |
| `domain` | `domain` | Contract + extraction supported; current flow adapters emit `None`, and the investigation evidence projection does not carry it, so incidents from those adapters yield zero domain observables until telemetry exists. |
| `url` | `url` | Same as domain. |
| `file_hash` | `file_hash` | Same as domain (hex md5/sha1/sha256 only). |

Normalization (`observables.py`, stdlib only): `ipaddress` for IPs
(compressed IPv6 canonicalized, malformed rejected), lowercased IDNA domains
with trailing-dot stripping, `http(s)` URLs with validated hosts, lowercase
hex hashes of length 32/40/64. Anything else returns `None` and is never
looked up. Usernames, hostnames, and process names are deliberately NOT
observable types: they are environment-local identities, not IOCs.

## 3. Provider interface

`ThreatIntelProvider` (`providers.py`): a side-effect-free ABC with
`name: str` and `lookup(observable) -> ThreatIntelResult`. Only the
normalized `(type, value)` pair is handed over — never raw events, labels,
or incident context. Unknown observables are a `classification: "unknown"`
answer, not an error. Hard failures raise `ThreatIntelError` (or any
exception), which the enrichment layer converts to per-observable
unavailable. Registry: `provider_registry()`; selection via
`threat_intel_provider` setting.

## 4. Local test provider

`LocalThreatIntelProvider` (`name = "local-test"`) reads
`services/threatintel/catalog.json` (`catalog_version: local-test-v1`).
Fixtures use only reserved space: TEST-NET-1/2/3 (RFC 5737), `2001:db8::/32`
(RFC 3849), `.invalid` / `example.com` (RFC 2606), and the empty-string
SHA-256 test vector. Every result carries `metadata.fixture: true` and the
UI renders the "fixture (test intelligence — not real threat data)" banner.
Benchmark labels are never consulted; an event labeled `Attack` whose IP is
absent from the catalog still returns `unknown`.

## 5. Enrichment lifecycle

`GET /api/v1/incidents/{id}/threat-intelligence`:

1. Load incident + detections + bounded evidence sample (same
   `EVIDENCE_SAMPLE_LIMIT = 200` as the investigation view; ORM rows, so
   `domain`/`url`/`file_hash` columns are readable when present).
2. `extract_observables(rows)`: deterministic `(type, normalized, source)`
   order, deduplicated, source-attributed.
3. `enrich_incident(...)`: cache check → `provider.lookup` → stamp
   `retrieved_at` → cache store; detection linkage via evidence-ID
   intersection; failure → `available: false` + error string.
4. Response: `{incident_id, provider, available, error, observables}`.

Unknown provider name → `200` with `available: false` and an explanatory
error (investigation keeps working). Unknown incident → `404`.

## 6. Traceability

`observable → event_ids (sample) + event_count → detection_ids →
incident_id → intelligence result`. Counts are exact; ID lists are bounded
and sorted. `bucket_event_ids` semantics are untouched (enrichment only
reads `evidence_event_ids` for linkage).

## 7. Caching strategy

`ThreatIntelCache`: process-local, TTL-bounded (`threat_intel_cache_ttl_seconds`,
default 3600), keyed `(provider, type, normalized_value)`. No new database
table — this matches the existing read-through UEBA/MITRE enrichment
architecture. The cache exists so a future network provider never repeats
external work for the same observable inside the TTL window. Cross-worker
duplication is acceptable (correct, at most once per worker per window).

## 8. Failure behavior

Enrichment is never critical path: detection, correlation, incidents, risk,
UEBA, MITRE, investigation, and recommendations all run without it. A
provider exception degrades only its observables to `available: false`;
the endpoint still returns `200` with per-item errors (plus a summary in
`error`). Provider outages can never 500 the investigation or lose data.

## 9. Privacy boundary

- Only `(observable type, normalized value)` may leave the process for a
  lookup. No raw events, payloads, labels, user/host inventory, or incident
  context.
- No API keys in code, logs, or database rows (none exist in this slice).
- No benchmark or security-event data is sent anywhere: this slice performs
  zero network I/O (covered by a test that blocks sockets).
- Future providers must document exactly which observables are transmitted,
  under what consent/contract, before being enabled.

## 10. Future external-provider integration

1. Subclass `ThreatIntelProvider` (e.g. `OtxProvider`) in `providers.py`;
   implement `lookup` with a caller-supplied timeout
   (`threat_intel_timeout_seconds`), mapping provider verdicts onto the
   four classifications without overclaiming confidence.
2. Register behind `threat_intel_provider` + credential settings (env-only,
   never logged/stored); keep `local-test` as the default.
3. Reuse `ThreatIntelCache` for rate-limit friendliness; on HTTP 429/timeout
   raise `ThreatIntelError` so callers degrade to unavailable; never retry
   inline in the request path.
4. Attribute every result (`provider`, `reference`, `retrieved_at`) and keep
   classifications provider-scoped: a "malicious" from one feed must not be
   presented as platform verdict, must not change severity/risk, and must
   not trigger containment. Slice 39 recommendations stay unchanged;
   intel remains contextual evidence a future playbook may cite explicitly.
5. The provider stays optional and non-blocking: with credentials absent or
   the network down, investigation and recommendations work exactly as now.

## Non-goals (explicit)

Detection-time IOC matching (`matched_ioc` → `contextual_points` in risk)
is a separate, pre-existing mechanism and is unchanged. Enrichment never
feeds back into severity, risk, correlation, or incident creation.
