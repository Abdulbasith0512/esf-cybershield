# Slice 13D — FLOW-002 Performance Optimization

## 1. Problem
Profiling (Slice 13C) showed FLOW-002 consuming ~97% of detection time
(77.7s of ~74s on 20k rows); 100k rows exceeded a 5-minute cap, making
multi-million-row benchmarks impractical.

## 2. Original complexity
O(n × w): for every event position, the reference rebuilt the window slice
and re-filtered all of it for qualifying flows.

## 3. Root cause
`RepeatedAttempts.evaluate` re-ran the SYN/byte predicate over the entire
active 5-minute window on each new event instead of maintaining the count
incrementally. Dense sub-threshold traffic (large windows, no firing reset)
was the worst case.

## 4. Optimization approach
Per aggregation key, two deques maintained in (timestamp, event_id) order:
`window_all` (every event: timestamp, id, qualifying flag) and
`window_qual` (qualifying event rows only). Each event enters once and
leaves once (`ts - left.ts >= window`, identical exclusive-end rule);
firing clears both, matching the reference `start = end + 1` reset exactly.

## 5. Preserved semantics
Window (5 min), threshold (≥20), SYN > ACK, 10 KB byte cap, key, severity
HIGH, confidence `min(0.60 + 0.02*n, 0.9)`, head-10 + tail-10 evidence,
reason template, metadata keys, fingerprint construction: all unchanged.

## 6. Evidence preservation
Evidence is the same first-10 + last-10 qualifying rows in the same order;
insertion order equals the reference sort order, so `_bounded` slices
identically. Locked by equivalence tests comparing full evidence lists.

## 7. Determinism
Same grouping, same sort, same emission points; output sorted by fingerprint
downstream as before. Reruns and shuffled inputs verified identical.

## 8. Equivalence testing
`backend/tests/test_flow002_optimization.py`: frozen verbatim reference copy
plus 13 behavioral tests (A–M fixtures) and a perf comparison. All pass.

## 9. Performance measurements
- Unit perf (3,000 dense sub-threshold events): reference 2.28s →
  optimized 0.04s (**53×**), identical outputs.
- 10k real rows: 25.7s → 3.0s. 50k: 265.7s → 14.6s. 100k: killed at
  330s → **35.0s**. Results byte-identical across versions (same run_ids).

## 10. Real-data validation
10k/50k/100k on 02-14-2018.csv reproduce pre-optimization results exactly
(7 detections: FLOW-001 ×6, FLOW-005 ×1; same counts, same run_ids).

## 11. Remaining limitations
Other rules retain their own complexities (none currently binding).
Throughput is now adapter-bound (~9k rows/s); full 7.9M-row evaluation
remains a long batch job, not an interactive one.
