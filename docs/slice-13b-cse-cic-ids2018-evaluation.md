# Slice 13B — CSE-CIC-IDS2018 Flow Detection Evaluation

> **Evaluation only.** Labels are read AFTER detection for reporting.
> Nothing here tunes detectors, and benchmark numbers measure lab behavior,
> never production efficacy.

## 1. Objective

Measure the Slice 13A flow detectors against real CSE-CIC-IDS2018 telemetry
with a reproducible, bounded-memory harness.

## 2. Evaluation boundary

```
CSV → adapter → canonical events → FlowView → FLOW-001…006
    → DetectionResult → [labels read here] → metrics + report
```

Detector inputs are label-free telemetry. The label crosses the boundary
exactly once: post-hoc attribution of evidence IDs to observed labels.

## 3. Ground-truth attribution

Unit of evaluation: the **event**. A detection covers exactly its
`evidence_event_ids`. Covered events keep their own labels, so mixed-label
evidence splits deterministically (no invented attack label, no majority
vote). True/false positives/negatives follow from covered vs labeled sets.

## 4. Sampling

- Default: first `--limit` rows in file order (temporal, per file).
- `--sample N --sample-seed S`: deterministic label-blind reservoir sample.
- `--balanced N`: label-stratified sample. **Diagnostic only** — reported as
  such, never as natural-traffic behavior.
- Same files + selection + seed + config ⟹ identical results (run_id is a
  hash of inputs, not wall-clock).

## 5. Temporal methodology

Evaluate contiguous temporal ranges; never randomly mix adjacent flows in
the primary path. Rationale: adjacent rows share attacks, IPs, and bursts —
random splits leak attack context across boundaries and destroy the temporal
realism detectors exploit.

## 6. Metrics

Per rule: detections, covered events, TP/FP/FN/TN, precision, recall, F1,
FPR, positive/benign support. `None` (rendered `n/a`) wherever a denominator
is undefined — never silent zeros. Overall: unique-event coverage, totals.
No averaged F1. Per-label coverage tables read labels verbatim.

## 7. Large-file processing

`--chunk-rows N` streams bounded row blocks with a temporal overlap carry
(`--overlap-minutes`, default 40) so windowed rules see cross-boundary
context; detections union by fingerprint. FLOW-005 (session catalog) runs
once over a deterministic stride sample (`--session-cap`) instead — same
rule code, documented scope difference. A second streaming pass resolves
labels for covered IDs plus label totals, keeping memory bounded.

## 8. Reproducibility

Deterministic RNG, sorted outputs, content-hashed run IDs. Reruns must match
except runtime metadata.

## 9. Label isolation

AST/static tests assert production flow code never references label or
scenario tokens; behavioral tests assert relabeling changes metrics but
never detector outputs. `FlowView` cannot represent a label.

## 10. CLI usage

```powershell
python scripts/evaluate_cse_cic_ids2018.py --file 02-14-2018.csv --limit 10000
python scripts/evaluate_cse_cic_ids2018.py --file 02-20-2018.csv --limit 5000 --chunk-rows 2000
python scripts/evaluate_cse_cic_ids2018.py --file 02-14-2018.csv --sample 2000 --sample-seed 7
```

Filenames resolve under `data/public/cse_cic_ids2018/raw/`; absolute paths
work too. Output: `evaluation/cse_cic_ids2018/<run-id>/{summary.json,report.md}`
(git-ignored).

## 11. Output format

`summary.json`: run_id, files, params, stats, per_rule, overall,
label_coverage, false_positives (first 20, bounded), leakage_check.
`report.md`: the same, human-readable, with `n/a` for undefined metrics.

## 12. Limitations

- Flow-only files: no endpoint attribution; AUTH/UEBA-style signals absent.
- Sparse classes (SQL Injection: 34 rows) support counts only, not rates.
- Entropy fallback threshold is provisional.
- Session-scoped FLOW-005 uses stride sampling under chunked mode.
- Benchmark ≠ production efficacy.

## 13. Why benchmark results do not equal production efficacy

Lab captures differ from production in traffic mix, background realism,
label noise, and adversarial adaptation. These numbers compare detector
configurations against each other on fixed data; they say nothing about
unseen networks.
