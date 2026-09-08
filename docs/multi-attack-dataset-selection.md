# Multi-Attack Dataset Selection

## 1. Objective

Establish an independent multi-attack validation dataset for ESF CyberShield,
so rules with zero true-positive validation on the single-campaign 1M slice
(FLOW-002 brute force, FLOW-003 port-scan recall, FLOW-006 burst) can be
measured. Selection and freezing only — no detector execution, no benchmark,
no tuning (Slice 31).

## 2. Candidate Datasets

### CICIDS2017 (SELECTED)
- Provenance: Canadian Institute for Cybersecurity (CIC), University of New
  Brunswick. Official pages: unb.ca/cic/datasets/ids-2017.html;
  generation paper Sharafaldin et al. 2018 ("Toward Generating a New
  Intrusion Detection Dataset and Intrusion Traffic Characterization").
  Obtained in this environment as third-party HuggingFace mirror
  `bencorn/CICIDS2017` of the official CSV bundles (provenance caveat, see §10).
- Licensing: CIC datasets are publicly released for research use (cite the
  dataset paper); verify institutional terms before any non-research use. No
  license file ships in the mirror.
- Format: CICFlowMeter flow CSVs. Two variants exist: MachineLearningCSV
  (79 cols) and GeneratedLabelledFlows/TrafficLabelling (85 cols).
- Attack families: brute force (FTP/SSH-Patator), DoS (Hulk, GoldenEye,
  Slowloris, Slowhttptest), Heartbleed, web attacks, infiltration, botnet,
  PortScan, DDoS.
- Network features: full CICFlowMeter set incl. SYN/ACK flag counts, IPs,
  ports, protocol, per-flow bytes/packets.
- Size: ~5 days; day files 52–286 MB.

### UNSW-NB15 (evaluated, rejected as primary)
- Provenance: UNSW Canberra Cyber Range (IXIA PerfectStorm); official
  research.unsw.edu.au page; CC-BY-4.0 Zenodo mirror (10140547); 2.54M rows,
  9 families (Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic,
  Reconnaissance, Shellcode, Worms); freely downloadable.
- Fatal limitation: Argus/Bro-derived 49 features contain NO per-direction
  SYN/ACK flag counts (only handshake durations), so FLOW-002 and the
  FLOW-003 SYN-probe discriminator — the exact validation gaps — cannot be
  exercised. Different timestamp model (epoch Stime) and schema would also
  require a full new adapter. Retained as a future flag-independent
  cross-check candidate (FLOW-001/004/005/006 only).

### Bot-IoT / TON_IoT (evaluated, rejected)
- IoT-specific telemetry and schemas; incompatible with the CICFlowMeter
  field contract without major adapter work; not representative of the
  enterprise traffic the engine targets.

### CIC-DDoS2019 (evaluated, rejected)
- Same-producer CICFlowMeter family, but DoS-only: adds no attack-family
  diversity beyond the current LOIC-HTTP slice.

### Local CSE-CIC-IDS2018 02-14 (evaluated, rejected as primary)
- Already on disk (341 MB): Benign 667,626 + FTP-BruteForce 193,360 +
  SSH-Bruteforce 187,589 with full schema compatibility. Rejected as the
  multi-attack source: same producer, testbed family, and generation
  pipeline as the current benchmark — weakest independence. Documented
  fallback if external acquisition ever regresses.

## 3. Candidate Comparison

| Candidate | Families | SYN/ACK flags | Timestamps | IPs/ports | Labels | Independence | Effort | Verdict |
|---|---|---|---|---|---|---|---|---|
| CICIDS2017 labelled flows | 8+ incl. scan+brute | Yes | Yes (min) | Yes | Yes | Same-producer caveat | Low (field map) | SELECT |
| UNSW-NB15 | 9 | No | Yes (epoch) | Yes | Yes | Strong | High (new adapter) | Reject (flags) |
| Bot-IoT/TON_IoT | IoT-narrow | Partial | Yes | Partial | Yes | Strong | High | Reject (schema) |
| CIC-DDoS2019 | DoS-only | Yes | Yes | Yes | Yes | Same-producer | Low | Reject (no diversity) |
| CSE 02-14 local | Brute ×2 | Yes | Yes | Partial (no Src IP) | Yes | Weak | Zero | Fallback only |

## 4. Selected Dataset(s)

CICIDS2017 GeneratedLabelledFlows (TrafficLabelling) day files: Friday
PortScan afternoon + Tuesday brute-force day. Rationale: (a) only candidate
carrying the missing families with compatible SYN/ACK flags and timestamps;
(b) exact published-figure matches (row and label counts) verify mirror
fidelity; (c) smallest defensible combination (2 files, 277 MB of the
519 MB acquired). Wednesday DoS and Thursday web/infiltration are approved
follow-ups, not frozen now.

## 5. Attack-Family Coverage

| Attack family | Present? | Source label(s) | Validation relevance |
|---|---|---|---|
| Port scanning / recon | Yes | PortScan (158,930) | FLOW-003 recall (currently unvalidated) |
| Brute force | Yes | FTP-Patator (7,938), SSH-Patator (5,897) | FLOW-002 (zero TP ever) |
| DoS/DDoS | No | — | Covered by 1M slice |
| Web attack | No | — | Future (Thursday file) |
| Botnet/C2 | No | — | Future |
| Infiltration/lateral | No | — | Future (Thursday has only 36 flows) |
| Exfiltration | No | — | Future |
| Abnormal proto/service | Partial | Rare-protocol background | FLOW-005 generality |

## 6. Working Subset Definition

No subsetting: both day files are frozen COMPLETE (286,467 + 445,909 =
732,376 rows, smaller than the 1M benchmark). Full-file freeze eliminates
selection bias by construction; no row was chosen, filtered, or reordered
for detector behavior (no detector has run on this data).

## 7. Dataset Integrity

- `data/public/cicids2017/` — see manifest JSON for paths, SHAs, counts,
  timestamp ranges, label distributions (paths below are relative to repo).
- Friday PortScan: 101,874,777 bytes, SHA-256
  `7e2ddaa80a5849ba629463296b6128436c161b4a32e8034bb5beae06b0c45e08`,
  286,467 rows, labels BENIGN 127,537 / PortScan 158,930, 2017-07-07
  01:00→03:29 file-clock (≈13:00→15:29 capture; 12-hour clock, see §10).
- Tuesday brute force: 174,696,560 bytes, SHA-256
  `ae9c88e10c41a8eb1ff454ae98bc513454925097d0b0b57180f94e79de445815`,
  445,909 rows, labels BENIGN 432,074 / FTP-Patator 7,938 / SSH-Patator
  5,897, file-clock 01:00→12:59.
- Bundle zips (acquisition only, git-ignored):
  MachineLearningCSV.zip `c3f26274…7928` (235,102,953 B),
  GeneratedLabelledFlows.zip `7bdbef28…150ea27a` (283,876,488 B).

## 8. Detector Isolation

Labels are evaluation-only: frozen CSVs are read by a future Slice-32
adapter into `evaluation_only` metadata exactly like the CSE adapter; no
detector interface changes; AST/leakage tests extend to the new adapter.

## 9. Adapter Requirements

Field map (2017 verbose → canonical; headers carry leading spaces):
Flow ID→identity basis, Source IP→Src IP, Source Port→flow-kept,
Destination IP→Dst IP, Destination Port→Dst Port, Protocol (same 6/17
coding observed), Timestamp→parsed per §10, Flow Duration, Total Fwd
Packets→Tot Fwd Pkts, Total Backward Packets→Tot Bwd Pkts, Total Length
of Fwd/Bwd Packets→TotLen, Flow Bytes/s (same name), SYN/ACK Flag
Count→flag counts, Label→evaluation_only (BENIGN normalizes via existing
case-insensitive rule; attack names pass through verbatim). No required
field is missing. Gaps for Slice 32: timestamp meridian rule, minute
resolution (ties by source_row, already engine-supported), 85-vs-80 column
shape (adapter must be header-driven, as the CSE adapter already is).

## 10. Limitations

- Same-producer family as the current benchmark (CIC/CICFlowMeter/B-profile
  methodology); independence is at scenario/traffic level, not producer level.
- Third-party mirror (not UNB direct — UNB site unreachable from sandbox
  except CMS pages); mitigated by exact published-figure matches on rows,
  labels, and attack windows.
- Minute-resolution timestamps (no seconds); sub-minute ordering falls back
  to source-row order.
- 12-hour clock without meridian: Friday-afternoon file reads PM
  (attack 13:55–15:29 appears as 1:55–3:29, verified against documented
  windows); Tuesday mixes AM/PM halves — Slice 32 must fix and validate a
  per-file meridian rule (monotonic file order makes flips observable).
- No web/botnet/infiltration/exfiltration in frozen pair (documented above).
- CICIDS2017-ML-CSV variant (also acquired) is REJECTED for evaluation: no
  Timestamp/IP/Protocol columns — timestamp-less, entity-less rows cannot
  feed time-ordered detection without fabricating telemetry.

## 11. Freeze Decision

Frozen for Slice 32 adapter + validation design (no detection yet):
Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv and
Tuesday-WorkingHours.pcap_ISCX.csv under `data/public/cicids2017/raw/`,
with SHAs and distributions above and in
`docs/multi-attack-validation-manifest.json`.
