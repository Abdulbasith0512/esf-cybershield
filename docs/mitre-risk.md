# MITRE ATT&CK Mapping + Risk Scoring (Slice 5)

## Why map to ATT&CK

Detections say *what was observed*; ATT&CK hypotheses suggest *what attacker
behavior it might represent*, in a vocabulary SOC analysts share. Every
mapping below is a hypothesis grounded in rule telemetry - never proof a
technique was used.

## Telemetry vs hypothesis

- **Observed telemetry**: failed logons, process parent/child, IOC string
  match, byte counts. Facts from events.
- **Inferred behavior**: "this looks like brute force". Rule-level judgment.
- **ATT&CK hypothesis**: "consistent with T1110". Catalog lookup, qualified
  language ("potential association"), moderate confidence. Skipped entirely
  when evidence is insufficient.

## Static catalog (`project-static-v1`)

`backend/app/services/mitre/catalog.json` (technique definitions) +
`mapping.py` (rule-to-technique rows with rationale + confidence). No live
MITRE API, no downloads; same input + catalog = same output. Version is
embedded in every `MitreMapping.catalog_version`; mappings must never change
silently.

| Rule | Technique | Tactic | Conf | Rationale |
|---|---|---|---|---|
| AUTH-001 | T1110 Brute Force | Credential Access | 0.85 | fails-then-success matches brute force |
| AUTH-003 | T1078 Valid Accounts | Persistence | 0.55 | new-source use of valid identity; window-relative |
| PROC-001 (P1) | T1059 Cmd/Script Interpreter | Execution | 0.80 | shell spawned by service host |
| PROC-001 (P2) | T1140 Deobfuscate/Decode | Defense Evasion | 0.75 | encoded-command indicator |
| PROC-002 | T1059 | Execution | 0.80 | configured suspicious parent-child pair |
| NET-001 | T1071 App Layer Protocol | C2 | 0.70 | lab-controlled indicator over app protocol |
| DATA-001 | T1048 Exfil Alternative Protocol | Exfiltration | 0.60 | large transfer; volume is not proof |
| AUTH-002 | - | - | - | heuristic only, no technique supported |
| NET-002 | - | - | - | volume only, never tunneling |

Duplicates collapse per (technique, rule); provenance preserved as one entry
per source rule (e.g. T1059 via PROC-001 and via PROC-002).

## Risk: definitions

- **Detection confidence**: is this rule signal valid (0-1)?
- **Correlation score** (`Incident.confidence`): do these detections belong
  together (0-1)?
- **Risk score** (0-100 int): how urgently should this be investigated?
  Prioritization, not probability of compromise.

## Formula (all weights in `RiskConfig`)

severity base LOW 10 / MEDIUM 25 / HIGH 45 / CRITICAL 60
+ 8 per distinct rule (cap 24)
+ int(10 x mean detection confidence)
+ 1 per unique evidence event (cap 10)
+ IOC present 12 + suspicious process 8
+ transfer scaled 5-12 by bytes/threshold doublings
+ sequence 10 (3-chain) / 15 (4-chain)
+ 3 per distinct tactic (cap 12)
= clamp 0-100, rounded int.

Repeats (NET-001 x4) add evidence/context only - distinct-rule, unique-event
and distinct-tactic math means duplicates never multiply risk linearly.

## Bands (configurable)

0-24 LOW, 25-49 MEDIUM, 50-74 HIGH, 75-100 CRITICAL. Band is independent of
`Incident.severity`: severity describes the story, band describes priority.

## Breakdown and explanation

`RiskBreakdown{severity,diversity,confidence,evidence,sequence,mitre,
contextual,total}` - every term inspectable; `total` always equals the sum.
`risk_explanation` cites only present evidence, mapped techniques, and band.

## Validation (10k, seed 42 - actual run)

914 detections -> 689 incidents. Risk bands: MEDIUM 366, HIGH 68,
CRITICAL 255; min/median/max 40/40/100; mean 56.3. Only one incident
scores 100 (the credential-compromise story below); sub-100 CRITICALs are
IOC singles (130), PROC pairs (50), brute+new-IP pairs (31), night-brute
triples (27), and IOC+transfer pairs (16) - each verified to satisfy the
strict link predicate (traced). `credential_compromise_001`:

- Severity CRITICAL, Risk 100 (CRITICAL band). Raw sum 157 capped at 100;
  the cap binding on the richest story is documented, not tuned away.
- Breakdown: severity 60, diversity 24, confidence 8, evidence 9,
  sequence 15, mitre 12, contextual 29 (IOC 12 + process 8 + transfer 9).
- Techniques: T1110 (AUTH-001), T1078 (AUTH-003), T1059 x2 (PROC-001/002),
  T1071 (NET-001), T1048 (DATA-001); 5 tactics.
- `benign_volume`: 0 detections, therefore 0 incidents and no risk.
- AUTH-003-only incidents: none survive merging (all share evidence with a
  sibling detection); single-rule MEDIUM incidents score ~40 (MEDIUM band).

## Limitations

- Static catalog covers 6 rules; novel tradecraft has no mapping.
- Volume-only signals contribute little without sequence/IOC context.
- Fixed weights are analyst-tuned priors, not learned optima.
- Synthetic validation is lab-only, not production evidence.
