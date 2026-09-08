# CICIDS2017 Adapter Design

## Dataset Source

Canadian Institute for Cybersecurity (CIC), University of New Brunswick:
unb.ca/cic/datasets/ids-2017.html; generation paper Sharafaldin et al. 2018.
Acquired in this environment as third-party HuggingFace mirror
`bencorn/CICIDS2017` of the official CSV bundles (see
`docs/multi-attack-dataset-selection.md` for the provenance caveat and
published-figure verification). Research use; cite the dataset paper.

## Frozen Files

- `data/public/cicids2017/raw/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`
  (286,467 rows; BENIGN 127,537 / PortScan 158,930; SHA-256
  `7e2ddaa8…0c45e08`).
- `data/public/cicids2017/raw/Tuesday-WorkingHours.pcap_ISCX.csv`
  (445,909 rows; BENIGN 432,074 / FTP-Patator 7,938 / SSH-Patator 5,897; SHA-256
  `ae9c88e1…445815`).

## Header Mapping

Headers stripped for lookup only; source CSVs untouched. Verbose
TrafficLabelling names map to canonical CICFlowMeter keys consumed by
`FlowView`'s allowlist (same contract as the CSE adapter): Total Fwd
Packets→Tot Fwd Pkts, Total Backward Packets→Tot Bwd Pkts, Total Length of
Fwd/Bwd Packets→TotLen Fwd/Bwd Pkts, SYN/ACK/RST Flag Count→SYN/ACK/RST Flag
Cnt, FIN Flag Count→FIN Flag Cnt, Fwd/Bwd Header Length (same),
Init_Win_bytes_forward/backward→Init Fwd/Bwd Win Byts, plus Avg Fwd/Bwd
Segment Size. All other columns preserved verbatim (stripped) under
`raw_event.flow`; `Label` stays out of `flow`. Top level: Source IP→source_ip,
Destination IP→destination_ip, Destination Port→destination_port (0–65535),
Protocol (same 6/17/1 coding observed), TotLen→bytes_sent/received.

## Timestamp Interpretation

Day-first 12-hour clock, minute resolution (e.g. `7/7/2017 2:53`).
Meridian is frozen per-file session context, validated against published
capture chronology — never guessed per row: Friday-afternoon file adds 12h
(attack 13:55–15:29 appears as 1:55–3:29); Tuesday full-day file maps 8–11
to morning, 12 to noon, 1–5 to +12h; any other hour is rejected, never
guessed. Rationale: weekday consistency (2017-07-04/07 fall on Tue/Fri only
under day-first order) plus attack-window alignment. Naive timestamps are
interpreted as UTC, matching CSE convention. Sub-minute ties fall back to
source-row order (engine sorts timestamp + event_id).

## FlowView Mapping

`src_ip/dst_ip` (ipaddress-validated, null when absent/invalid), `dst_port`,
`protocol`, `timestamp`, `packets` (Tot Fwd/Bwd), `bytes`
(TotLen Fwd/Bwd), SYN/ACK/FIN/RST via the alias map above. `user/host`
always null (absent from source, never fabricated); Src Port has no
canonical field and stays inside `raw_event.flow`.

## TCP Flag Mapping

Adapter normalizes verbose flag names to the exact keys `FlowView` reads;
missing/empty flags stay absent from the normalized flow so `flow_value()`
defaults (0.0) apply — identical to CSE missing-value semantics. Absence
therefore never fabricates a probe signal (`0 > 0` is false).

## Event Identity

`uuid5(NAMESPACE, dataset|adapter_version|source_file|source_row)` with
`SOURCE_ID=cicids2017`, version `cicids2017-v1`, and a deterministic
namespace constant (`uuid5(DNS, "esf-cybershield.cicids2017")` — derived,
not random). 1-based source rows captured at read time; order-independent;
label-independent.

## Raw Telemetry

All non-label columns preserved (stripped verbatim + documented aliases);
nothing forensically useful is dropped. Labels live only in
`raw_event.evaluation_only`.

## Label Isolation

`Label` → `evaluation_only.label` verbatim (`BENIGN` kept verbatim;
`normalize_label` maps it post-hoc per existing policy). No label, family
name, or evaluation metadata touches event identity, FlowView projection,
or detector inputs (AST-tested over the datasets package).

## Missing Values

Unparseable timestamp/port → `RejectReason` (`bad_timestamp`/`bad_port`)
and counted; unknown session filename → `bad_session`; ambiguous meridian
hours → `bad_timestamp`. Numerics follow CSE losslessness (`_flow_number`);
negatives → null for byte counts. Full-file validation: **zero rejections**
on both frozen files.

## Determinism

Same file → byte-identical event-ID streams across independent runs
(Friday `65bcc5e2…04dfa`, Tuesday `21c10edf…60832` over 732,376 IDs);
732,376 unique IDs, no collisions.

## Validation Results

732,376 rows read/converted, 0 rejected; label counts match the frozen
manifest exactly; Friday range 2017-07-07T13:00→15:29Z (150 unique minutes);
Tuesday 2017-07-04T08:53→17:00Z (488 unique minutes); attack labels fall
inside documented capture windows. Throughput ~5.8k rows/s single-pass
streaming (126 s). No detector executed.

## Known Limitations

Minute resolution (ties by row); 12-hour clock needs the frozen meridian
rule (new day files need explicit session mapping or fail closed);
flow-only telemetry (no user/host); third-party mirror provenance mitigated
by exact published-figure matches.

## Slice 32 Decision

Adapter accepted for Slice 33 validation design. No detector evaluation
performed; no precision/recall exists for this data.
