# Correlation Engine (Slice 4)

**Detection is not Incident.** A detection is one analytical signal with
evidence. An incident is multiple related signals forming a coherent
security story. Correlation assembles stories; it never proves compromise.

## Architecture

```
DetectionResult[] -> correlate(detections, events_by_id?)
  -> dedupe by detection fingerprint
  -> sort chronologically
  -> resolve entities (user, host) per detection
  -> pairwise strict links -> union-find components
  -> one Incident per component (singles included)
```

- Package `backend/app/services/correlate/`: `models` (Incident),
  `config` (CorrelatorConfig), `fingerprint` (UUIDv5 identity),
  `rules` (link/score/severity/title/reason), `engine` (plumbing only).
- Pure domain layer: no DB, no API, no ML, no ground-truth access.

## Incident model

`incident_id` (deterministic UUIDv5), `title`, `severity`,
`status` in OPEN/INVESTIGATING/RESOLVED (default OPEN), `confidence`
(= correlation score), `reason`, `detection_ids` + `evidence_event_ids`
(unique, sorted, complete), `first_seen/last_seen`,
`metadata{rule_ids, user, host, correlation_score, sequence_hits,
detection_count, event_count}`.

## Signals

Same **user** AND same **host** AND **<=30 min** gap (configurable
`window_minutes`) AND (**shared evidence event** OR **recognized sequence
pair**: AUTH-001+PROC-001/002, AUTH-001+NET-001, PROC-001/002+NET-001/DATA-001,
NET-001+DATA-001, AUTH-001+DATA-001). Entities resolve from evidence-event
columns via `events_by_id`, falling back to rule metadata; `None`/`unknown`
never match; ambiguous evidence never matches.

## Fingerprint

`incident:<sorted detection IDs>` hashed to UUIDv5. Same membership gives
the same ID; reruns and reorderings are identical. Duplicate detections
dedupe first.

## Score and severity (config-centralized)

`correlation_score` = w_same_user .20 + w_same_host .15 + w_temporal .20 +
w_shared_evidence .25 (best link) + w_sequence .15 + w_multi_rule .05, plus
0.10 x mean detection confidence; singles score from rule severity plus
confidence. Severity: single takes rule severity; HIGH pair gives HIGH;
3-chain (AUTH-001+PROC+NET) gives HIGH; full 4-chain (+DATA-001) gives
CRITICAL.

## Titles and reasons

Composition-driven (`Potential Credential Compromise Sequence`, ...; singles
get `<Rule name> - Single-Signal Observation`). Reasons cite actual rule IDs,
user/host, and score with qualified language only (never "confirmed").

## Validation (10k, seed 42, corrected data model - actual run)

914 detections -> **689 incidents**: MEDIUM 432, HIGH 256, CRITICAL 1.
Sizes: 498 singles, 163 pairs, 27 triples, 1 nine-signal story.
`credential_compromise_001` forms the CRITICAL story
(`Potential Credential Compromise with Suspicious Data Transfer`,
confidence 1.00): AUTH-001 + AUTH-003 + PROC-001 + PROC-002 + NET-001 x4 +
DATA-001, 9 detections / 9 events over ~29 min. Note: 2 of the 9 events
belong to a `suspicious_network` chain that randomly shares the same
user+host and overlaps the window - merged legitimately under the strict
rule (recognized sequence pairs), and per-detection evidence keeps the
story auditable. `benign_volume` yields 0 detections and therefore
0 incidents (no signal, no story). All 125 AUTH-003 merge only via shared
evidence with a sibling detection on the same login event - no giant
merges. Reruns and input shuffles are fingerprint-identical.

## Limitations

- Entity resolution needs evidence events; metadata-only mode is conservative.
- Fixed 30-min window can split slow-burn activity (tunable).
- No cross-host campaign tracking yet (explicitly requires extra signals).
- Volume-only signals (NET-002, DATA-001) link only via entity+sequence.
- Synthetic validation is lab-only, not production evidence.
