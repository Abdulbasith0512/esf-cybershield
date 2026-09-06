# UEBA + Isolation Forest (Slice 6)

## What UEBA means here

User and Entity Behavior Analytics: aggregate per-entity behavior over fixed
time windows, learn what normal looks like unsupervised, and score deviations.
It **complements** deterministic rules (AUTH-001 still fires on its own) and
adds an independent ML signal for later incident enrichment. It replaces
nothing.

## Features (v `ueba-features-v1`)

Grain: **(user, fixed UTC hour)**. 12 numeric columns, fixed order:
`event_count, auth_event_count, failed_auth_count, successful_auth_count,
failed_auth_ratio, unique_source_ip_count, new_source_ip_count,
unique_destination_count, dns_event_count, outbound_bytes_log1p,
process_event_count, unusual_hour_event_count` (day = 08:00-20:00 UTC).
Identifiers group rows only, never become features. Missing telemetry uses
documented zero/absent defaults; duplicates dedupe by `event_id`; input order
is normalized by timestamp sort. `new_source_ip_count` is causal (prior
windows only - no future leakage).

## Baselines and cold start

Per-user history yields READY / INSUFFICIENT_HISTORY / COLD_START
(`min_history_windows=5`, `min_history_events=10`, global fallback counts).
Status is reported in result metadata; it gates interpretation, never scoring.

## Model (v `ueba-iforest-v1`)

`sklearn.ensemble.IsolationForest(n_estimators=200, contamination=0.05,
random_state=42)` on standardized features. Raw `score_samples` are negated
and min-max normalized with **train** extremes (0 = least, 1 = most
anomalous); the flag threshold is the top-5% train quantile - an operational
anomaly-rate choice, not a label-tuned cutoff. An anomaly score is **not a
probability of compromise**.

## Train/eval separation

Train: normal-only rows, 2026-09-01..03 (scenario filter lives in
`scripts/train_ueba.py`, never in the feature pipeline). Eval: all rows,
2026-09-04..05, transform-only (no refit). Artifacts in `models/ueba/`
(git-ignored) + `manifest.json` (dataset hash, rows, columns, hyperparams,
versions, threshold).

## Ground-truth leakage prevention

`scenario_id/scenario_type/synthetic/seed` appear nowhere in
`services/ueba/` (AST-tested), nowhere in feature columns (tested), and
nowhere in scaling/threshold/model selection. Labels are used only for
post-hoc evaluation reporting, clearly marked synthetic-only.

## Validation (10k, seed 42 - actual run)

- Train: 1,828 rows from 5,343 normal events (days 1-3); 12 features.
- Eval: 1,306 rows from 4,045 events (days 4-5). Anomaly rate 112/1,306
  (8.6%). Score min/max/mean/median 0.000/1.000/0.248/0.162.
- Per-scenario (dominant type per window): brute_force 21/21 flagged (mean
  1.00); credential_compromise chain window flagged 1.00 with context
  {14 events, 3 failed, new IP, 4.29 GB outbound, 2 process events};
  unusual_login 14/30; benign_volume 5/8 flagged (mean 0.64) - volume
  driven, legitimate, not special-cased; data_spike 1/18 (only the 4 GB
  window); normal 69/1,196 (5.8%, near the operational rate).
- Honest misses: suspicious_network 0/19 and suspicious_process 1/13 -
  a lone connection or a few process events inside an hour window look
  statistically normal at this grain; the rule engine covers these.
- Retrain reproducibility: identical scores; manifests identical except
  `created_at`. Save/load round-trip: identical scores.
- Timings (dev machine): feature build ~0.05 s, train ~3.5 s,
  eval scoring ~2 s for 10k events.

## Limitations

- Hour grain misses sub-hour bursts (rule engine covers those).
- Unsupervised: no labeled precision claims; synthetic F1 is lab-only.
- Cold-start entities rely on global fallback.
- Feature set is first-pass; DNS/process-heavy tradecraft may be faint.
- Model retraining policy is a future slice.
