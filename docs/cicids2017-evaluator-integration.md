# CICIDS2017 Evaluator Integration

## Integration Boundary

```
CICIDS2017 CSV → Cicids2017Adapter → events (+ separate label map)
→ prepare() → FlowView → detect_flows() → DetectionResults → correlate()
→ incidents → post-hoc label join → metrics
```

Labels travel beside events in `evaluation_only` and are joined by event ID
only after detection. Detector-facing input is the `FlowView` projection.

## Adapter → FlowView Contract

Adapter emits EventCreate-compatible dicts (canonical network fields,
`raw_event.flow` numerics under FlowView allowlist keys, `evaluation_only`
labels). `prepare()` adds `_ts`; `build_views()` projects the allowlisted
subset. Verified field-by-field on PortScan/FTP/SSH/BENIGN representatives.

## Label Isolation

`prepare()` passes `raw_event` through untouched — the boundary is
`FlowView`, whose allowlist cannot represent labels (proven: view dumps
contain no label strings; stripping `evaluation_only` changes nothing
downstream). Relabeling alters metrics inputs only.

## Event Identity

UUIDv5 over `cicids2017|cicids2017-v1|<file>|<row>`; stable across runs,
label-independent, file- and row-scoped; no collisions in 732,376 IDs.

## Timestamp Ordering

Day-first 12-hour clock with frozen per-file meridian rule (UTC); minute
resolution with source-row/event-ID tie-breaks. Ordering is label- and
filename-independent beyond the documented meridian context.

## Rule Compatibility

All FLOW rules' required fields are supplied: timestamps, endpoint
identity, ports, protocol, packets/bytes, SYN/ACK/FIN/RST counts,
`Flow Byts/s`, `Flow Pkts/s`. Missing flags stay absent (fail closed).

## Correlation Compatibility

`DetectionResult` identity, fingerprints, evidence/bucket IDs, and
timestamps flow into `correlate()` unchanged; incident assembly is
rule-agnostic. Verified on adapter-derived records.

## Post-Hoc Label Join

`event_id → evaluation_only.label`, resolved after detection/dedup from
the separate label map. Detector never consumes it.

## Leakage Validation

AST scan over the datasets package (incl. `cicids2017*.py`) plus relabel-
and strip-invariance behavioral tests; existing flow/correlate leakage
suites unchanged and green.

## Determinism

Identical inputs yield byte-identical views, fingerprints, incidents, and
JSONL artifacts (fingerprint order, sorted keys).

## Validation Results

10 integration tests green; full backend suite green; 732,376-row adapter
validation (0 rejected, exact label counts, byte-identical ID streams).
No detector benchmark on CICIDS2017 has been run.

## Known Limitations

Minute-resolution timestamps; 12-hour clock needs the frozen meridian rule
(new day files fail closed); flow-only telemetry (no user/host); FIN/UDP
scan coverage follows the FLOW-003 discriminator limits; third-party mirror
provenance mitigated by exact published-figure matches.

## Slice 33 Decision

CICIDS2017 is ready for actual detector evaluation. Next: frozen multi-attack
benchmark design (Slice 34), reusing the unchanged official CLI procedure.
