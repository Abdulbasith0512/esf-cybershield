# Slice 7 - UEBA Incident Enrichment

## Purpose

UEBA provides an independent behavioral anomaly signal attached to incidents
for analyst context. It answers: "How anomalous is the observed behavior
relative to the learned behavioral baseline?"

## Design decision: risk is unchanged

Deterministic risk answers: "What rule-based evidence and correlated signals
make this incident risky?" UEBA answers a different question. In this slice
the two are displayed side by side:

```
Incident
 |-- Deterministic evidence (detections, correlation)
 |-- MITRE ATT&CK hypotheses
 |-- Deterministic risk (score, band, breakdown) - UNCHANGED by UEBA
 |-- UEBA behavioral anomaly evidence (available/score/flag/version/window/context)
```

`IncidentWithUeba{enriched: EnrichedIncident, ueba: UEBAIncidentEvidence}`.
The wrapped `EnrichedIncident` is never modified - risk regression is proven
by asserting score/band/breakdown equality before and after attachment.

## Attachment semantics

Observations are built once over in-scope events (preserving causal IP
history) and scored once with the loaded model. Per incident, the user comes
from `incident.metadata` (None means honestly unavailable); candidate
observations must match the entity, end at or before `incident.last_seen`
(no future leakage), and overlap incident evidence. All overlapping windows
attach (max score / any-flag summary). States: unavailable, available-clean,
available-anomalous - never a magic number, never "confirmed threat".

Versions come from the model (`model.config`), matching
`models/ueba/manifest.json` (`ueba-iforest-v1`). Feature provenance is honest
`feature_context` (observed nonzero values), never causal attribution.

## Validation (10k, seed 42 - actual run)

- 10,000 events -> 914 detections -> 689 incidents (unchanged).
- UEBA attach: 170 available+flagged, 519 available+clean, 0 unavailable.
  Anomaly-score min/med/max 0.005/0.360/1.000.
- Deterministic risk regression: every incident's score, band, and breakdown
  byte-identical before and after attachment (`risk unchanged by UEBA: True`).
- `credential_compromise_001` (1125cb0a...): severity CRITICAL, risk 100 /
  CRITICAL unchanged; UEBA available, score 1.0, flag True,
  model `ueba-iforest-v1`, window 08:50:05 -> 09:19:31; two overlapping
  observations (08:00 clean 0.56, 09:00 anomalous 1.0 with 14 events,
  3 failed logons, new IP, 4.29 GB outbound, 2 process events).
- `benign_volume`: 0 incidents, nothing to attach.
- Rerun determinism IDENTICAL; label leakage 0; no-future-leakage,
  shuffle-invariance, and AST leakage gates green in `pytest`.

## Limitations

- UEBA trained/evaluated on synthetic data; anomaly is not maliciousness.
- Isolation Forest attribution is limited to observed context values.
- Top-5% flag policy is an operational choice carried over from Slice 6.
- Hour grain can miss sub-hour incident dynamics.
- No production accuracy claim; deterministic risk intentionally unchanged.
