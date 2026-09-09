# CICIDS2017 Multi-Attack Benchmark

First multi-attack validation after single-campaign tuning (Slices 13–28).
Establishes an honest baseline: which existing rules fire on which attack
families. Not a tuning exercise; no thresholds were touched for this run.

## Inputs

- `data/public/cicids2017/raw/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`
  (286,467 rows, SHA-256 `7e2ddaa8…0c45e08`)
- `data/public/cicids2017/raw/Tuesday-WorkingHours.pcap_ISCX.csv`
  (445,909 rows, SHA-256 `ae9c88e1…445815`)
- Total 732,376 rows. Command: `evaluate_cicids2017.py --limit 0
  --chunk-rows 50000 --overlap-minutes 40 --flow005-full --order time`.
- Frozen selection/manifest: `docs/multi-attack-dataset-selection.md`,
  `docs/multi-attack-validation-manifest.json`.

## Attack families

PortScan (158,930, 2017-07-07 13:05→15:23Z), FTP-Patator (7,938,
09:17→10:30Z), SSH-Patator (5,897, 14:09→15:11Z). One attack episode per
distinct non-benign label; labels post-hoc only, never into detection.

## Metrics

Evidence (capped samples), bucket (complete `bucket_event_ids`), and
incident (real correlation replay) levels, per the shared methodology:
`docs/slice-13b-cse-cic-ids2018-evaluation.md`. Detections/incidents JSONL
artifacts accompany every run.

## Ordering

Deterministic timestamp + event_id ordering; minute ties by source row.

## Artifacts

`evaluation/cicids2017-multi-attack-official/<run_id>/`: `summary.json`,
`report.md`, `detection_metrics.json`, `bucket_metrics.json`,
`incident_metrics.json`, `attack_coverage.csv`, `detections.jsonl`,
`incidents.jsonl`.

## Limitations / non-claims

- 732k rows across two days; not the full CICIDS2017 corpus.
- Third-party mirror provenance (exact published-figure matches recorded).
- Minute-resolution, 12-hour-clock timestamps (frozen meridian rule).
- This benchmark does not prove production efficacy or broad recall.
