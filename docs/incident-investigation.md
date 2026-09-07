# Slice 10 — Incident Investigation

The investigation page (`/incidents/[id]`) is a **read-only presentation**
of existing persisted analysis: correlated detections, MITRE mappings,
deterministic risk, UEBA evidence, and the underlying event evidence.
The UI performs no security decisions.

## Sections

Header (title, copyable ID, severity, status, confidence, window, duration)
→ risk + UEBA summary tiles → investigation summary (backend reason,
verbatim) → attack story (stages derived strictly from present rule IDs
and evidence event types; absent stages omitted, never invented) →
attack timeline (hydrated evidence sorted by timestamp asc, `event_id`
tiebreak) → detection evidence (persisted IDs grouped by MITRE
`source_rule_id`, with an honest disclaimer that full detection objects
are not exposed) → MITRE hypotheses → UEBA observations → risk breakdown
bars (displayed, never recomputed) → evidence table (selectable rows +
`EventDetail` + capped raw-JSON `<pre>`) → technical context (guarded
narrow of `incident_metadata`; neutral labels only, never "attacker IP").

## Evidence retrieval

`useIncidentEvidence(ids)`: dedupes IDs, fans out bounded parallel
`GET /api/v1/events/{id}` via `Promise.allSettled` on one abort signal,
sorts deterministically. One 404/unreachable event degrades to a
row-level warning; the page never mistakes failure for empty evidence.
No batch endpoint exists; worst observed incident has 9 events.

## States and safety

Every section has loading/error/empty states; 404 renders “Incident not
found”. All backend strings render as React text (XSS-safe; covered by
tests). Severity/anomaly use text + glyph, never color alone.

## Limitations

No status mutations, comments, timelines beyond evidence, graphs, RAG,
or hybrid risk. Detection cards show IDs only until a read-only
detections endpoint exists.
