# Final Evaluation (Slices 13–34 Consolidated)

## 1. Evaluation scope

Two frozen benchmarks, one deterministic engine: CSE-CIC-IDS2018 1M
(`evaluation/slice22-1m/6cb7243a7ce9/`, post-Slice-21 code) and CICIDS2017
732,376 rows (`evaluation/cicids2017-multi-attack-official/f9dde9888580/`,
post-Slice-35 code). Three metric levels everywhere: evidence (capped
samples), bucket (complete contributor sets), incident (correlation replay).

## 2. Frozen datasets

| Dataset | Rows | Attack episodes | Attack labels | Purpose |
|---|---|---|---|---|
| CSE-CIC-IDS2018 1M | 1,000,000 | 1 | DDoS-LOIC-HTTP | Flood-volume validation |
| CICIDS2017 pair | 732,376 | 3 | PortScan, FTP-Patator, SSH-Patator | Multi-family generality |

- CSE: `data/public/cse_cic_ids2018/working/02-20-2018-1m.csv`, SHA-256
  `5669cfe2…774bcb`.
- CICIDS2017: Friday PortScan (286,467, `7e2ddaa8…0c45e08`) + Tuesday brute
  force (445,909, `ae9c88e1…445815`); 732,376 rows total.

## 3. Reproducibility methodology

UUIDv5 event identity, timestamp + event-ID ordering, 50k time-ordered
chunks with 40-min overlap, FLOW-005 full second pass, post-hoc labels
only, deterministic fingerprints, byte-identical JSONL reruns (proven on
CICIDS2017: identical fingerprints, metrics, and artifact bytes).

## 4. Detection-layer metrics

| Dataset | Precision | Recall | F1 | FPR |
|---|---|---|---|---|
| CSE 1M | 0.0453 | 0.00144 | 0.00279 | 0.0412 |
| CICIDS2017 | 0.0514 | 0.00292 | 0.00552 | 0.0166 |

| Dataset | Detections | Composition |
|---|---|---|
| CSE 1M | 1285 | 001:306, 003:973, 004:5, 005:1 |
| CICIDS2017 | 492 | 001:492 (others 0) |

## 5. Bucket-level evaluation

| Dataset | TP | FP | Precision | Episodes hit | Recall |
|---|---|---|---|---|---|
| CSE 1M | 46 | 1239 | 0.0358 | 1/1 | 1.0 |
| CICIDS2017 | 27 | 465 | 0.0549 | 3/3 | 1.0 |

Buckets are complete contributor sets; a bucket is TP iff it intersects an
episode. Empty/unknown buckets are unavailable, never FP.

## 6. Incident-level evaluation

| Dataset | Incidents | Attack-hit | Benign | Precision | Recall |
|---|---|---|---|---|---|
| CSE 1M | 1001 | 9 | 992 | 0.0090 | 1.0 |
| CICIDS2017 | 485 | 23 | 462 | 0.0474 | 1.0 |

No incident FPR is reported anywhere: benign episodes are not a partition,
so a conventional denominator would mislead.

## 7. Attack-episode coverage

| Attack | Events | Buckets | Hit | Hit incidents |
|---|---|---|---|---|
| DDoS-LOIC-HTTP | 576,191 | 46 (001×45, 005×1) | yes | 9 |
| PortScan | 158,930 | 15 (001) | yes | 11 |
| FTP-Patator | 7,938 | 7 (001) | yes | 7 |
| SSH-Patator | 5,897 | 5 (001) | yes | 5 |

One episode per distinct non-benign label; each counted at most once.

## 8. Per-rule behavior

- FLOW-001: the only rule firing on CICIDS2017 (492); 45/46 CSE bucket TPs.
  Volume detection generalizes across floods and brute/scan bursts.
- FLOW-002: silent on both (brute windows never reach 20 qualifying 5-min
  flows; SSH traffic is ACK-heavy). Unvalidated, not refuted.
- FLOW-003: 973→0 on CSE after density+SYN gates; silent on CICIDS2017
  because all 158,930 PortScan flows carry SYN Flag Count 0 (probe gate
  correctly finds no probes). Recall unvalidated everywhere (no labeled scan).
- FLOW-004: 5 benign CDN bursts on CSE; silent on CICIDS2017. Narrow,
  honest behavior after the median redesign.
- FLOW-005: one giant TP bucket per campaign (414,902-event TCP/80 on CSE);
  silent on CICIDS2017 (no dense novel pair). Novelty+peak semantics hold.
- FLOW-006: silent on both (50k-pps floor never reached). Unvalidated.

## 9. Cross-dataset comparison

| Rule | CSE-CIC-IDS2018 | CICIDS2017 | Interpretation |
|---|---|---|---|
| 001 | 306 (45 TP) | 492 (27 TP) | Generalizes: floods, scans-as-bursts, brute force |
| 002 | 0 | 0 | Needs 20 qualifying/5 min; unvalidated |
| 003 | 973→0 (gates) | 0 (no SYN) | Gate correct; recall unvalidated |
| 004 | 5 benign | 0 | Conservative post-redesign |
| 005 | 1 TP | 0 | Campaign-dependent by design |
| 006 | 0 | 0 | Threshold never reached; unvalidated |

## 10. False-positive analysis

CSE residual: 261 moderate infra bursts (001: DNS/metadata/HTTP), 5 CDN
bursts (004). CICIDS2017: 465 benign buckets, all 001 volume on background.
No rule produces unexplained FP families; remaining FP is the documented
price of volume-sensitive detection on infra-heavy traffic.

## 11. Known operating-envelope limitations

Single-campaign-per-dataset recall; minute-resolution 2017 clocks; no
user/host/auth telemetry (flow-only); FIN/UDP scan shapes outside the 003
discriminator; slow-burn and application-layer attacks unaddressed.

## 12. Evidence-cap limitation

Evidence caps (20/20/20/3/5/20) bound event recall structurally (CSE
ceiling ≈5%; exhibited by the 414,892-attack bucket with 0 evidence TP).
Bucket recall is the honest detection-coverage measure; event recall
measures evidence sampling.

## 13. Label-isolation methodology

Adapter-embedded `evaluation_only` labels; FlowView allowlist projection;
strip/relabel-invariance proofs; AST scans; post-hoc joins by event ID.
Detectors never consume ground truth.

## 14. Determinism results

CICIDS2017 full rerun: identical counts, fingerprints, bucket/incident
metrics, and byte-identical JSONL. CSE reruns historically consistent;
unit determinism (repeat/shuffle) green.

## 15. What can and cannot be claimed

May claim: deterministic flood-volume detection with episode recall 1.0 on
both frozen sets; measured FP removal per redesign slice with zero
collateral change; reproducible artifacts. Must NOT claim: high recall
across attack types, scan/burst recall, production accuracy, zero FP.

## 16. Future evaluation requirements

Per `docs/multi-attack-validation-plan.md`: web/botnet/infiltration/exfil
families, 002/003/006 positive validation, no campaign-specific tuning.
