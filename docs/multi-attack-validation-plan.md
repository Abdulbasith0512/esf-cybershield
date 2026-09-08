# Multi-Attack Validation Plan

## 1. Objective

Validate the detection engine across multiple independent attack families
rather than continuing to optimize against DDoS-LOIC-HTTP. Each family must
be able to confirm — or refute — the rules built for it.

## 2. Required Attack Families

Validation matrix (minimum):

- DoS/DDoS (covered: LOIC-HTTP slice)
- Port scanning (required for FLOW-003 recall)
- Brute force, e.g. SSH/FTP password guessing (required for FLOW-002)
- Web attack, e.g. SQL injection / XSS (new family)
- Botnet/C2-like traffic, e.g. periodic beaconing (new family)
- Infiltration/lateral movement (new family)
- Data exfiltration / bulk egress (new family)
- Abnormal protocol/service behavior (required for FLOW-005 generality)

Do not claim that these are already present in the current 1M dataset.
They are not — it contains one flood campaign plus background.

## 3. Rule-to-Attack Validation Matrix

| Rule | Intended coverage | Currently validated | Future validation required |
|------|-------------------|---------------------|----------------------------|
| FLOW-001 | High-volume flood / connection burst | LOIC-HTTP flood (TP) | Other flood shapes, UDP floods |
| FLOW-002 | Repeated connection attempts | None | Brute-force family: TP rate, FP on benign SSH/admin |
| FLOW-003 | Port scanning | FP removal only (no scan truth) | Labeled scan family: recall by scan speed (fast/slow), FIN/UDP limits |
| FLOW-004 | Byte-rate anomaly | FP reduction on benign bulk | Exfil-style bulk vs benign bulk separation |
| FLOW-005 | Novel protocol/port behavior | One TP instance + FP removal | Novelty on multi-service data; ephemeral handling |
| FLOW-006 | High-rate DoS-like burst | None | Burst-rate family above 50k pps |

## 4. Evaluation Rules

- Labels are post-hoc only; no labels may enter detector execution.
- No attack-specific tuning: thresholds fixed before evaluation.
- No IP allowlists, no port allowlists, no attack-specific exceptions.
- Each attack family evaluated independently against frozen detector code.
- Metrics at detection, bucket, and incident levels; evidence caps reported
  separately from bucket recall.
- Deterministic artifacts (detections/incidents JSONL) for every run.

## 5. Metrics

Detection-level: precision, recall, F1, FPR.
Bucket-level: precision, episode recall, bucket TP/FP.
Incident-level: precision, episode recall, singleton/multi-detection
distribution, incident size distribution.
Operational: runtime, memory, determinism, evidence integrity, fingerprint
uniqueness.

## 6. Acceptance Criteria

No arbitrary numerical thresholds. Acceptance requires:
- no unexplained regression on previously validated attack behavior;
- deterministic, byte-identical reruns;
- no label leakage (AST + behavioral tests);
- no attack-specific exceptions in code or config;
- each intended rule receives meaningful positive validation;
- false positives investigated by behavioral family before any change;
- any detector change justified independently of the test set (fixtures,
  threat semantics, engine consistency — never benchmark maximization).

## 7. Next Validation Sequence

1. Obtain/prepare independent multi-attack validation data (frozen, hashed).
2. Freeze evaluation datasets; record SHAs.
3. Run current detector without modification.
4. Measure rule-by-rule performance (detection/bucket/incident).
5. Identify the highest-impact general weakness (read-only forensics).
6. Investigate it read-only; rank root causes with evidence.
7. Implement at most ONE defensible change (slices 18/21/24/27 pattern).
8. Rerun ALL affected validation sets, including the 1M LOIC slice.
9. Compare against frozen baselines; regressions block acceptance.
10. Repeat only when justified; stop tuning any single campaign on weak evidence.
