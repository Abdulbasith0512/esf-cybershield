# Slice 13 — Network-Flow Detection & Real-Data Evaluation

> **Design-only slice.** Nothing here is implemented. No production code,
> thresholds, dependencies, or contracts change as a result of this document.
> Expectations in §13 are predictions to be tested, not measured results.

## 1. Objective

Give the existing deterministic pipeline meaningful signal on CSE-CIC-IDS2018
flow telemetry, where current rules are correctly silent (no user/host/auth
fields exist). The output is a set of network-flow detectors that consume
observable network behavior — never dataset labels — and emit standard
`DetectionResult` objects into the unchanged correlation → risk → UEBA chain.

## 2. Current Telemetry Constraints

- Canonical fields available on every record: `timestamp` (UTC, second
  precision), `event_id` (deterministic), `event_type="network_connection"`,
  `source="cse_cic_ids2018"`, `destination_port`, `protocol` (TCP/UDP/ICMP or
  raw), `bytes_sent` / `bytes_received` (may be null), `source_ip` /
  `destination_ip` (null except `02-20-2018.csv`), `Src Port` only inside
  `raw_event.flow`. `host`, `user`, and all process/auth fields are null.
- Discriminative flow features (`Flow Duration`, packet counts/lengths,
  flag counts, rates, IAT statistics, window sizes) exist **only** in
  `raw_event.flow`. Existing rules must never read `raw_event`
  (AST-enforced invariant protecting against label/scenario leakage).
- Timestamps are **not globally ordered** in source files; second precision
  creates frequent ties. Event identity is
  `dataset|adapter_version|file|1-based source row`, so duplicates stay
  distinct and row order never affects identity.
- Zone-less capture timestamps are interpreted as UTC (documented
  assumption). Files span single days (02-14 through 03-02); `02-20` holds
  ~7.9M rows and needs chunked evaluation. `02-16`, `02-28`, `03-01`
  contain a stray mid-file `Label` header row artifact the adapter must
  skip (treat a row whose `Label` value equals the literal `Label` as
  malformed and reject it).
- Label distribution is heavily imbalanced per file (e.g. 02-14:
  667,626 Benign / 193,360 FTP-BruteForce / 187,589 SSH-Bruteforce;
  02-22: 1,048,213 Benign vs 34 SQL Injection). Sparse classes cannot
  support quantitative claims.
- Note: `docs/cse-cic-ids2018.md` identity table (row 57) is stale — it
  still describes the superseded content-hash identity. The implemented
  row-number strategy (same doc, Event ID section) is authoritative.

## 3. Detection Design

Six detectors are proposed; **F (asymmetric traffic) is dropped** —
single-direction ratios are normal for scans, backups, and streaming, so it
folds into DATA-001-adjacent context instead of standing alone.

### FLOW-001 — High Connection Rate
- **Hypothesis:** an endpoint receiving far more flows per unit time than its
  recent baseline is experiencing scan, brute-force, or DoS-like pressure.
- **Fields:** `timestamp`, `destination_ip` (or global fallback),
  `destination_port`.
- **Key:** `destination_ip` when present, else the constant `GLOBAL`.
- **Window:** 60 s sliding, step 60 s (non-overlapping emission).
- **Threshold:** count ≥ max(50, 5 × median of prior 10 windows for the key);
  minimum evidence 50 flows. Centralized in config.
- **Severity:** MEDIUM. **Confidence:** `min(0.55 + 0.05 * log2(n/threshold), 0.9)`.
- **Evidence:** first 10 + last 10 event IDs of the window plus count in
  metadata (bounded at 20).
- **Reason:** `"High-rate connection behavior detected: {n} flows to {key} within 60 seconds (baseline median {m})."`
- **Coverage:** works flow-only (global key) and endpoint-aware.
- **False positives:** flash crowds, backups, monitoring sweeps.
- **SOC value:** cheapest triage signal; points at *where*, not *what*.

### FLOW-002 — Repeated Connection Attempts (brute-force-like)
- **Hypothesis:** many short flows to one service port with SYN-heavy flags
  and little transferred data indicate password guessing or service probing.
- **Fields:** `destination_ip` (or global), `destination_port`,
  `SYN Flag Cnt`, `ACK Flag Cnt`, `TotLen Fwd Pkts`, `TotLen Bwd Pkts`,
  `Flow Duration`.
- **Key:** `(destination_ip|GLOBAL, destination_port)`.
- **Window:** 5 min sliding.
- **Threshold:** ≥ 20 flows with `SYN>ACK` and `TotLen Fwd Pkts + TotLen Bwd Pkts < 10 KB`;
  minimum evidence 20 flows.
- **Severity:** HIGH. **Confidence:** `min(0.60 + 0.02 * n, 0.9)` capped by
  the fraction of qualifying flows.
- **Evidence:** qualifying flows only (bounded 20: earliest 10 + latest 10).
- **Reason:** `"Repeated connection attempts detected: {n} short SYN-heavy flows to port {p} within 5 minutes."`
- **Coverage:** flow-only capable; sharper with endpoint data.
- **False positives:** health checks, load-balancer probes, NAT keepalives.
- **SOC value:** directly maps to the observed FTP/SSH brute-force days.

### FLOW-003 — Port-Scan-like Behavior
- **Hypothesis:** one source contacting many distinct destination ports in a
  short window indicates reconnaissance.
- **Fields:** `source_ip` (required), `destination_port`, `timestamp`.
- **Key:** `source_ip`.
- **Window:** 5 min sliding.
- **Threshold:** ≥ 15 distinct destination ports from one source;
  minimum evidence 15 flows (one per port, earliest per port).
- **Severity:** MEDIUM. **Confidence:** `min(0.55 + 0.02 * distinct_ports, 0.85)`.
- **Evidence:** earliest flow per distinct port, capped at 20.
- **Reason:** `"Port-scan-like behavior detected: {k} distinct destination ports contacted from {ip} within 5 minutes."`
- **Coverage:** **endpoint-aware only.** Flow-only fallback: global
  destination-port entropy per minute (documented as weak; short windows
  with Shannon entropy above a calibrated ceiling); clearly labeled
  `port-entropy anomaly`, never `scan`.
- **False positives:** vulnerability scanners the SOC itself runs, P2P apps.
- **SOC value:** the only reconnaissance-shaped signal available.

### FLOW-004 — Flow Byte-Rate Anomaly
- **Hypothesis:** flows moving bytes far faster than the recent per-key norm
  indicate bulk transfer or tunnel abuse.
- **Fields:** `Flow Byts/s`, `destination_ip` (or global), `TotLen Fwd Pkts`,
  `TotLen Bwd Pkts`.
- **Key:** `destination_ip` or GLOBAL.
- **Window:** 60 s observation vs trailing 30-min rolling median.
- **Threshold:** bucket median `Flow Byts/s` (over buckets with ≥ 5 flows,
  `byte_min_bucket_flows`) ≥ 8 × rolling median with minimum 1 MB/s floor;
  minimum evidence 3 flows. Rationale for 5: the engine already requires 5
  observations for a trustworthy median (`byte_min_history_buckets`,
  `novelty_min_flows`); single transfers can never trip the rule. Slice-20
  1M analysis showed max-of-bucket fired on lone benign bulk transfers while
  the LOIC attack (sub-MB/s flows) never qualified — median fixes the
  single-transfer trigger without moving the ratio, floor, windows, or
  history depth.
- **Severity:** MEDIUM. **Confidence:** scales with log-distance from median,
  capped at 0.85.
- **Evidence:** top-3 flows by byte rate plus baseline summary in metadata
  (`median_byts`, `baseline_median`, `ratio`).
- **Reason:** `"Anomalous flow byte rate detected: median {x} B/s vs {m} B/s recent median."`
- **Coverage:** flow-only capable.
- **False positives:** legitimate bulk transfers, backups, video.
- **SOC value:** rate counterpart to DATA-001's volume view.

### FLOW-005 — Protocol/Port Anomaly
- **Hypothesis:** traffic on unusual protocol/port combinations (e.g. TCP/4443
  bursts, non-standard ports for the observed service mix) deserves a look.
- **Fields:** `protocol`, `destination_port`.
- **Key:** global catalog per evaluation period.
- **Window:** session-scoped (whole input): build catalog of
  (protocol, port) pairs in the first temporal third; flag pairs unseen in
  the catalog with ≥ 5 flows in the remainder.
- **Threshold:** unseen pair + ≥ 5 flows + peak ≥ 50 flows within one UTC
  minute bucket (`novelty_min_peak`). Rationale: Slice-17 1M analysis showed
  novelty alone fires on routine ephemeral-port churn (1612 FP, most pairs
  seen ≤ ~11 times spread thin); the peak gate reuses the engine's existing
  60-second meaningful-volume floor (`rate_min_count`), so transient churn
  stays silent while sustained novel services still fire. IANA ephemeral
  range (49152–65535, configurable) is reported in metadata for analyst
  context; it does not change firing in v1.
- **Severity:** LOW. **Confidence:** fixed 0.5 (weakest signal by design).
- **Evidence:** up to 5 earliest unseen-pair flows. **Bucket:** all pair
  members. Metadata adds `peak_minute_count` and `ephemeral_port`.
- **Reason:** `"Unusual protocol/port combination observed: {proto}/{port} ({n} flows), unseen in baseline period."`
- **Coverage:** flow-only capable.
- **False positives:** new legitimate services reaching minute-level volume;
  sparse-but-persistent odd-port background is now silent by design.
- **SOC value:** low-cost novelty tripwire, not an alert cannon.
- **Label-free guarantee:** decision uses only timestamps, protocol, and
  ports; no label/ground-truth access (AST-tested).
- **Chunk/streaming:** the full second-pass replica implements identical
  catalog, minute-bucket, and peak semantics over the whole stream
  (cross-validated byte-for-byte against the rule); chunk-local windows do
  not apply.
- **Known limitations:** pairs sustaining moderate volume below the peak
  floor stay silent; minute buckets are UTC-epoch aligned (boundary effects
  possible for bursts straddling a minute edge).

### FLOW-006 — DoS-like High-Volume Burst
- **Hypothesis:** extreme packet/flow surges in short windows indicate
  denial-of-service pressure (GoldenEye/Hulk/LOIC/HOIC days).
- **Fields:** `Flow Pkts/s`, `Tot Fwd Pkts`, `SYN/RST/ACK Flag Cnt`,
  `timestamp`, `destination_ip` (or global).
- **Key:** `destination_ip` or GLOBAL.
- **Window:** 30 s sliding.
- **Threshold:** ≥ 500 flows AND ≥ 50k packets/s aggregate in-window;
  minimum evidence 20 flows.
- **Severity:** HIGH. **Confidence:** `min(0.65 + 0.05 * log10(packets_per_s/50k), 0.9)`.
- **Evidence:** 20 highest-rate flows.
- **Reason:** `"Denial-of-service-like traffic pattern detected: {f} flows, {p} packets/s within 30 seconds."`
- **Coverage:** flow-only capable (global key on DoS days).
- **False positives:** flash crowds, CDN bursts.
- **SOC value:** the only detector shaped for the DoS/DDoS roster.

## 4. Detector-to-Field Mapping

| Detector | Canonical fields | `raw_event.flow` fields |
|---|---|---|
| FLOW-001 | `timestamp`, `destination_ip?`, `destination_port` | — (counts only) |
| FLOW-002 | `timestamp`, `destination_ip?`, `destination_port` | `SYN Flag Cnt`, `ACK Flag Cnt`, `TotLen Fwd Pkts`, `TotLen Bwd Pkts`, `Flow Duration` |
| FLOW-003 | `timestamp`, `source_ip` (required), `destination_port` | — (+ entropy fallback uses port distribution) |
| FLOW-004 | `timestamp`, `destination_ip?` | `Flow Byts/s`, `TotLen Fwd Pkts`, `TotLen Bwd Pkts` |
| FLOW-005 | `protocol`, `destination_port`, `timestamp` | — |
| FLOW-006 | `timestamp`, `destination_ip?` | `Flow Pkts/s`, `Tot Fwd Pkts`, `SYN/RST/ACK Flag Cnt` |

Detectors never read `Label`, `scenario_*`, or any key outside these two
columns. Canonical-vs-flow access is mediated by a typed `FlowView`
(§16); rules receive `FlowView`, never the raw event dict.

## 5. Aggregation and Window Semantics

- Aggregation keys are restricted to: `source_ip`, `destination_ip`,
  `(source_ip, destination_port)`, `(destination_ip, destination_port)`,
  `protocol`, `destination_port`, or the constant `GLOBAL` fallback.
  `host`/`user` keys are forbidden (always null; grouping by null would
  merge the world).
- All windows slide over **event time**, computed from sorted timestamps.
  Emission is non-overlapping per key (`start = end + 1` after firing,
  mirroring NET-002) so one burst yields one detection.
- Flow-only files: detectors keyed on `destination_ip` degrade to `GLOBAL`;
  FLOW-003 requires `source_ip` and otherwise emits only its weak entropy
  variant. The coverage matrix in §9 is normative.
- Minimum-evidence floors (§3) prevent single-flow detections.

## 6. Determinism and Event Identity

- Inputs are sorted by `(timestamp, event_id)` before evaluation (reuse
  engine `prepare()`); input order never affects output.
- Windows are **inclusive-start, exclusive-end** (`[t, t+W)`); ties broken
  by `event_id` ascending. Boundary events belong to exactly one window.
- Fingerprints reuse the existing mechanic:
  `rule_id + ":" + ",".join(sorted(evidence_ids))` → UUIDv5, giving stable
  `detection_id`s across reruns and shuffles, independent of Python
  object ordering or dataframe positions.
- Duplicate-looking flows stay distinct: identity is
  `dataset|adapter_version|file|source_row`, and evidence selection keeps
  each row's own ID. Never collapse by content.

## 7. Evidence Strategy

- Evidence is always actual `SecurityEvent` IDs from the evaluated window.
- Bounded: representative head (earliest N/2) + tail (latest N/2), N ≤ 20;
  full counts and window summaries go in `metadata` (`count`, `window`,
  `key`, `baseline`).
- Qualifying-subset rules (FLOW-002/004/006) attach only qualifying flows,
  never the whole window.
- Empty evidence is impossible by construction (minimum-evidence floors).

## 7b. Evidence Sample vs Bucket Membership

- `evidence_event_ids`: capped analyst-facing sample (§7 caps: 20/20/20/3/5/20
  for FLOW-001..006). Determines `fingerprint` and `detection_id`.
- `bucket_event_ids`: complete label-free set of event IDs that satisfied the
  rule's firing condition (full window/bucket/window-qualifying members).
  Sorted, unique, deterministic; never read from labels.
- The two have different purposes: evidence identifies a detection for
  analysts; bucket membership lets downstream evaluation measure whether a
  detection intersected attack activity without penalizing capped samples.
- Fingerprint, evidence caps, thresholds, and semantics are unchanged by
  exposing the bucket set.

## 8. Severity and Confidence

- Severity is fixed per rule (FLOW-001/003/004/005: MEDIUM or LOW;
  FLOW-002/006: HIGH), reflecting signal strength, not label matching.
- Confidence formulas in §3 scale with observable excess over threshold
  (counts, log-distances), clamped to [0,1] and rounded to 3 decimals like
  existing rules. Confidence answers "how far past the tripwire", never
  "probability of attack".
- Reason strings state counts, keys, windows, and baselines; banned
  vocabulary: `confirmed attack`, `compromise`, `tunneling`, `exfiltration`
  as assertions. Required hedges: `-like behavior`, `detected`,
  `anomaly` (§3 wordings are normative).

## 9. Flow-Only vs Endpoint-Aware Coverage

| Detector | Flow-only (9 files) | Endpoint-aware (02-20) | Required fields | Limitations |
|---|---|---|---|---|
| FLOW-001 | Yes (global key) | Yes (per-Dst-IP) | timestamp, Dst Port | Global key is noisy on busy days |
| FLOW-002 | Yes | Yes | Dst Port, SYN/ACK counts, lengths | Health-check FPs |
| FLOW-003 | Weak entropy variant only | Yes (full) | Src IP + Dst Port | No IPs invented for the 9 files |
| FLOW-004 | Yes | Yes | Flow Byts/s | Bulk-transfer FPs |
| FLOW-005 | Yes | Yes | Protocol, Dst Port | Novelty ≠ malice; LOW severity |
| FLOW-006 | Yes (global key) | Yes | Pkt rates, flag counts | Flash-crowd FPs |

## 10. Label Isolation

`raw_event.evaluation_only.label` is used **only after inference**, for
scoring predictions against truth. It must not enter detector conditions,
thresholds, aggregation keys, fingerprints, reasons, severities,
confidences, correlation, risk, UEBA features, training, or calibration.
Enforcement: (a) `FlowView` exposes no label attribute — it is
structurally unrepresentable in rule code; (b) the existing AST leakage
test is extended to the new package with `Label` added to its target set
for rule modules only (adapter code legitimately moves the column into
`evaluation_only`); (c) a rename-invariance test: relabeling every row
(e.g. all → `X`) must produce byte-identical detections. Calibration
thresholds are set from benign-traffic quantiles and analyst judgment,
never from label-conditioned optimization.

## 11. Evaluation Methodology

- **Sampling:** temporal windows per file (§12), not random rows; report
  per-file, per-rule detection counts plus latency/runtime.
- **Metrics per rule:** precision, recall, F1 (where the positive class is
  non-sparse), false-positive rate, detection count, coverage (% of attack
  rows in flagged windows), runtime.
- **Overall:** micro-averaged F1 over evaluable (rule, file) pairs plus a
  qualitative FP review on benign-heavy windows.
- **Why naive random sampling misleads:** flows are autocorrelated —
  adjacent rows share attacks, IPs, and bursts. Random splits leak attack
  context across train/eval boundaries, inflate scores, and destroy the
  temporal realism the detectors exploit. It also oversamples the majority
  class unevenly across files with 34-row minorities.
- No production-efficacy claims; this benchmark measures lab behavior only.

## 12. Temporal Evaluation Split

Per file: sort by timestamp; use the **first 20% time span for threshold
calibration** (benign quantiles + smoke checks) and the **remaining 80%
for evaluation**. Rationale: attacks in these captures are bursty and
front-loaded in some files; a time split tests generalization to later,
unseen burst shapes, keeps adjacent flows together, and mirrors deployment
(calibrate on history, evaluate on the future). Never tune on the
evaluation span.

## 13. Metrics

Precision/recall/F1 per (rule, file) where positives ≥ 1,000 rows;
FPR on benign-majority windows; detection counts; evidence boundedness
(max evidence IDs per detection); runtime per 100k flows; determinism
(identical fingerprints on rerun + shuffle). Sparse classes (SQL
Injection: 34 rows; XSS: ≤151) are reported as counts only — no rates.

## 14. Expected Failure Modes

- **Healthy:** FLOW-002 fires on 02-14/02-15 brute-force windows with
  benign-window FPR near zero; FLOW-006 fires on Hulk/LOIC/HOIC bursts;
  FLOW-001 tracks DoS days; reruns byte-identical.
- **Over-sensitive:** benign flash windows trip FLOW-001/006 (thresholds
  too close to background quantiles); FLOW-005 fires on every new
  ephemeral service (catalog window too short).
- **Insufficient telemetry:** FLOW-003 silent on all 9 flow-only files
  except weak entropy blips; slowloris-style low-rate attacks fall below
  FLOW-006 floors (expected — document, don't lower floors to chase them).
- **Strongest expected:** FLOW-002 (FTP/SSH days), FLOW-006 (volumetric
  days). **Weakest:** FLOW-003 on flow-only data, FLOW-005 everywhere
  (by design — LOW tripwire).

## 15. Test Plan

Unit (synthetic dicts, no CSV): deterministic output; shuffle invariance;
timestamp ordering; equal timestamps (tiebreak); boundary timestamps
(inclusive/exclusive); duplicate-looking flows stay distinct; missing IPs
(flow-only skip vs global fallback); malformed numerics (null, not crash);
zero/near-zero durations (guard division); zero packet counts; very large
rates (no overflow, capped confidence); bounded evidence (≤ 20 IDs);
stable fingerprints (rerun + shuffle); label leakage (AST + rename
invariance); synthetic regression (existing 150+ tests green);
public-data evaluation (scripted, thresholds frozen).

## 16. Architecture

```
Public Dataset → Dataset Adapter → Canonical SecurityEvent
      → FlowView (flow-only projection, Label unrepresentable)
      → Network-Flow Detection (new flow_rules package)
      → DetectionResult → Existing Correlation → Risk + MITRE → UEBA → Dashboard
```

A **separate detector package** (`flow_rules/`, registered alongside —
not inside — the existing rule registry) best preserves modularity and
regression safety: existing rules, their AST invariant, and all green
tests stay untouched; the new package carries its own config namespace
(`flow_*` thresholds), its own AST leakage test (with `Label` in scope),
and its own evaluation harness. Promoting flow fields to canonical
columns was rejected (contract + migration churn for 79 columns);
pre-computed adapter features were rejected (changes adapter output shape
and idempotency surface).

## 17. Production/Streaming Considerations

- **Stateful windows:** per-key ring buffers of (timestamp, event_id,
  stratifying flags); watermarks at `max_seen - lateness_horizon`.
- **Bounded memory:** cap per-key buffers (evict oldest beyond
  `2 × max_window`); cap distinct keys with LRU + spill counters in
  metadata so eviction is observable, not silent.
- **Late/out-of-order events:** accept within horizon, recompute affected
  windows deterministically; drop-and-count beyond horizon.
- **State expiration:** per-key TTL of `max_window + horizon` of event
  time; global sweep on watermark advance.
- **Horizontal scaling:** partition by aggregation key hash
  (`destination_ip` / GLOBAL shard); all six detectors are key-local, so
  no cross-partition state is needed.
- **Deduplication:** `event_id` set per key-window (row identity already
  unique); idempotent replays collapse naturally.
- **Rate limiting:** per-key token buckets upstream of detectors so a
  single elephant flow source cannot starve co-located keys; limits
  themselves emitted as metadata, never silent drops.

## 18. Implementation Plan

- **13A — contracts/config:** `FlowView`, `flow_rules/` skeleton,
  `FlowConfig` namespace, AST test extension. No detector logic.
- **13B — detectors:** FLOW-001…006, one per reviewable unit, hedged
  reasons, bounded evidence.
- **13C — detector tests:** §15 unit battery; all existing tests green.
- **13D — evaluation harness:** temporal-split runner reusing the
  Slice-12B script pattern (read-only, labels post-hoc only).
- **13E — threshold calibration:** benign-quantile pass on first-20%
  spans; frozen before evaluation; documented, never label-optimized.
- **13F — integration:** register package in engine; verify correlation,
  risk, UEBA, dashboard unchanged; full regression + fresh 10k synthetic
  run.

## 19. Open Questions / Decisions Required

1. **09:00 UTC assumption for capture timestamps** — captures are local
   (Eastern) time; current code assumes UTC. Should flow windows use
   America/Toronto conversion (needs `tzdata` dependency) or keep the
   documented UTC assumption? Recommendation: keep UTC; windows are
   relative, so absolute offset rarely matters.
2. **FLOW-003 entropy fallback threshold** — needs benign-quantile data
   from 13E before a number is proposed; left symbolic in this design.
3. **02-20 evaluation cost** — 7.9M rows; recommend chunked streaming
   evaluation with bounded state (§17) rather than full in-memory runs.
4. **`Src Port` promotion** — currently flow-only. If a future detector
   needs it canonically, that is a contract change requiring its own
   review; out of scope here.
