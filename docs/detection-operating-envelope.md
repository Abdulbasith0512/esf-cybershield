# ESF CyberShield Detection Operating Envelope

## 1. Purpose

This document defines the empirically validated operating envelope of the
current deterministic network-flow detection layer (FLOW-001 through
FLOW-006). It states what has been demonstrated, on what data, and what
remains unvalidated — so future work extends evidence instead of
overfitting a single benchmark.

## 2. Frozen Evaluation Basis

- Dataset: CSE-CIC-IDS2018, working file
  `data/public/cse_cic_ids2018/working/02-20-2018-1m.csv`.
- Exact row count: 1,000,000 data rows.
- SHA-256: `5669cfe2b1704fa35846ef527f5a3c504802bd7fb8ab1d6b8970c3e02b774bcb`.
- Ordering: time-ordered evaluation, 50,000-row chunks, 40-minute overlap,
  FLOW-005 stream-global second pass, deterministic fingerprints.
- Labels are post-hoc only: they never enter detection, correlation, bucket
  construction, or incident assembly.
- Reproducibility: identical inputs and configuration yield byte-identical
  detections, incidents, and JSONL artifacts.
- The remaining ~6.9M source rows are excluded from all current evaluation
  claims. No claim below extends to them.

## 3. Rule Coverage Matrix

| Rule | Detection family | Validated TP evidence | Current FP evidence | Validated on DDoS campaign? | Status |
|------|------------------|-----------------------|---------------------|-----------------------------|--------|
| FLOW-001 | High connection rate per host | 45 TP buckets / 830 TP events on LOIC-HTTP flood | 261 benign infra-burst buckets | Yes | Validated detector for flood volume |
| FLOW-002 | Repeated SYN-heavy attempts | None (0 detections) | None | No | Awaiting multi-attack data |
| FLOW-003 | Port-scan-like behavior | None (0 TP; no labeled scan exists) | 0 detections after SYN-probe gate (was 94 session-chatter FP) | FP removal validated; recall unvalidated | Semantically filtered, recall open |
| FLOW-004 | Byte-rate anomaly | None (0 TP) | 5 benign CDN-burst buckets | Partial (FP characterized) | Robust to single spikes; attack fit open |
| FLOW-005 | Protocol/port novelty | 1 TP bucket (414,892-event TCP/80 flood bucket) | 0 FP after density gate | Yes (single instance) | Validated on one campaign; generalization open |
| FLOW-006 | High-volume burst | None (0 detections) | None | No | Awaiting multi-attack data |

Absence of detections/TPs for FLOW-002, FLOW-003, and FLOW-006 on this
campaign does NOT prove those rules ineffective — the campaign contains no
brute-force, scan, or burst-rate behavior for them to detect.

## 4. Validated Strengths

Demonstrated (Slice 16B/19/22/25/28 artifacts), without real-world extrapolation:
- Deterministic event identity (UUIDv5), ordering, and detection fingerprints.
- Evidence/bucket separation: capped analyst evidence vs complete contributor sets.
- Post-hoc label evaluation with leakage tests.
- FLOW-001 detection of the known DDoS campaign (recall 1.0 at bucket and incident level).
- FLOW-003 semantic filtering of session chatter (973 → 94 → 0, zero collateral change).
- FLOW-004 single-flow-spike robustness (1584 → 5).
- FLOW-005 novelty redesign (1613 → 1, attack bucket preserved).
- Network-aware correlation (4476 → 3897 → 2285 → 1001 → 199 incidents across slices, attack coverage preserved throughout).
- Incident persistence and bucket/incident-level evaluation.
- MITRE/risk enrichment and UEBA integration where implemented.

## 5. Known Limitations

### FLOW-001
Moderate single-service infrastructure bursts (DNS, cloud metadata, HTTP infra)
can resemble flood behavior at lower rates (261 FP buckets vs 45 TP).

### FLOW-002
No meaningful TP validation exists in the current attack campaign.

### FLOW-003
No labeled scan attack exists; scan recall remains unvalidated. The
discriminator emphasizes unanswered SYN behavior and therefore does not
cover FIN/UDP/non-SYN scanning behavior.

### FLOW-004
Only five benign survivors remain; broader attack-family validation is required.

### FLOW-005
Current frozen benchmark has one attack family and therefore limited
generalization evidence.

### FLOW-006
No meaningful TP validation exists in the current campaign.

### Dataset limitation
The benchmark represents one attack family and cannot establish broad
detector recall.

## 6. Claims We MAY Make

- "On the frozen 1M LOIC-HTTP slice, FLOW-001 detects the flood with bucket recall 1.0."
- "Session-chatter FLOW-003 false positives were removed (973 → 0) with zero change to other rules."
- "Single-transfer FLOW-004 false positives were removed (1584 → 5) with zero attack loss."
- "Ephemeral-port FLOW-005 false positives were removed (1613 → 1) with the flood bucket preserved."
- "All measurements are deterministic and reproducible from the frozen dataset."
- "Labels were resolved post-hoc only; detectors never consume ground truth."

## 7. Claims We MUST NOT Make

- "detects all network attacks"
- "high recall across attack types"
- "perfect port-scan detection"
- "production-ready detection accuracy"
- "proven zero false positives"
- "proven scan recall"

## 8. Current Decision

No further single-campaign detector tuning is justified at this stage.
The remaining false positives (261 moderate infra bursts, 5 CDN bursts) are
separable from true positives only by volume/rate thresholds calibrated on
this campaign, by service allowlists, or by protocol narrowing — all of which
would overfit one flood or blind real attack classes. Further tuning here
would trade measured generality for benchmark cosmetics.
