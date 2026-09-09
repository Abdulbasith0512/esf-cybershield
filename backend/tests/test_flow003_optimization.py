"""FLOW-003 optimization equivalence: frozen reference vs incremental.

The REFERENCE_SCAN function below is a verbatim frozen copy of the
pre-optimization PortScan._scan_mode loop (O(n*w) per-event rebuild). DO NOT
MODIFY it; it exists solely to prove the incremental implementation is
behaviorally identical. _dense_span was removed as dead code after the
optimization; its logic lives on inside this frozen copy.
"""

import sys
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.services.detect.common import prepare  # noqa: E402
from app.services.detect.flow.config import FlowConfig  # noqa: E402
from app.services.detect.flow.rules import PortScan  # noqa: E402
from app.services.detect.models import make_result  # noqa: E402
from test_flow_rules import flow as _flow  # noqa: E402

T0 = datetime(2026, 9, 3, 9, 0, 0, tzinfo=timezone.utc)
CFG = FlowConfig()
_n = 0


def flow(seconds=0, **kw):
    global _n
    _n += 1
    kw.setdefault("sip", "10.9.0.1")  # single source unless a test says otherwise
    return _flow(seconds=seconds, **kw)


def reference_scan(rule, pairs):
    """FROZEN reference: pre-optimization O(n*w) rebuild. DO NOT MODIFY."""
    window = timedelta(minutes=rule.config.scan_window_minutes)
    dense = timedelta(seconds=rule.config.scan_density_window_seconds)
    need = rule.config.scan_min_ports
    groups = {}
    for v, r in pairs:
        if v.source_ip:
            groups.setdefault(v.source_ip, []).append((v, r))
    out = []
    for ip, members in groups.items():
        members = sorted(members, key=lambda t: (t[0].ts, t[0].event_id))
        start = 0
        for end in range(len(members)):
            while members[end][0].ts - members[start][0].ts >= window:
                start += 1
            windowed = members[start:end + 1]
            by_port = {}
            for item in windowed:
                port = item[0].destination_port
                if port is not None and port not in by_port:
                    by_port[port] = item
            if len(by_port) < need:
                continue
            counts: Counter = Counter()
            distinct = 0
            low = 0
            span = None
            for high in range(len(windowed)):
                port = windowed[high][0].destination_port
                if port is not None:
                    if counts[port] == 0:
                        distinct += 1
                    counts[port] += 1
                while windowed[high][0].ts - windowed[low][0].ts >= dense:
                    old = windowed[low][0].destination_port
                    if old is not None:
                        counts[old] -= 1
                        if counts[old] == 0:
                            distinct -= 1
                    low += 1
                if distinct >= need:
                    span = windowed[low:high + 1]
                    break
            if span is None:
                continue
            by_dense = {}
            for item in span:
                port = item[0].destination_port
                if port is not None and port not in by_dense:
                    by_dense[port] = item
            probes = sum(1 for view, _ in by_dense.values()
                         if rule._is_probe(view))
            if probes / len(by_dense) <= rule.config.scan_unanswered_syn_fraction:
                continue
            chosen = [by_dense[p] for p in sorted(by_dense)[:20]]
            chosen.sort(key=lambda t: (t[0].ts, t[0].event_id))
            rows = [r for _, r in chosen]
            bucket_rows = [r for _, r in sorted(
                by_dense.values(), key=lambda t: (t[0].ts, t[0].event_id))]
            out.append(make_result(
                rule.rule_id, rule.name, rule.severity,
                min(0.55 + 0.02 * len(by_dense), 0.85),
                (f"Port-scan-like behavior detected: {len(by_dense)} distinct "
                 f"destination ports contacted from {ip} within 5 minutes."),
                rows,
                {"source_ip": ip, "distinct_ports": len(by_dense)},
                bucket=bucket_rows))
            start = end + 1
    return out


def optimized(rule, events):
    return [d for d in PortScan(rule.config).evaluate(prepare(events))
            if d.rule_name == "Port-Scan-like Behavior"]


def dumped(dets):
    return [(d.fingerprint, d.model_dump()) for d in dets]


def check_equivalent(events, rule=None):
    from app.services.detect.flow.rules import _pairs

    rule = rule or PortScan(CFG)
    pairs = _pairs(prepare(events))
    expected = dumped(reference_scan(rule, pairs))
    actual = dumped(optimized(rule, events))
    assert actual == expected
    return actual


def test_slow_accumulation_equivalent():
    evts = [_flow(seconds=i * 20, sip="10.1.2.3", dport=1000 + i) for i in range(15)]
    assert check_equivalent(evts) == []


def test_rapid_scan_equivalent():
    evts = [flow(seconds=i * 2, dport=1000 + i, syn=2, ack=0) for i in range(16)]
    assert len(check_equivalent(evts)) == 1


def test_boundary_equivalent():
    base = [flow(seconds=4 * i, dport=1000 + i, syn=2, ack=0) for i in range(14)]
    assert check_equivalent(base + [flow(seconds=60, dport=2000, syn=2, ack=0)]) == []
    assert len(check_equivalent(base + [flow(seconds=59, dport=2000, syn=2, ack=0)])) == 1


def test_mixed_probe_sessions_equivalent():
    evts = [flow(seconds=i * 2, dport=1000 + i, syn=2, ack=0) for i in range(7)]
    evts += [flow(seconds=14 + i * 2, dport=1007 + i) for i in range(8)]
    assert check_equivalent(evts) == []
    evts2 = [flow(seconds=i * 2, dport=1000 + i, syn=2, ack=0) for i in range(9)]
    evts2 += [flow(seconds=18 + i * 2, dport=1009 + i) for i in range(6)]
    assert len(check_equivalent(evts2)) == 1


def test_repeated_scans_equivalent():
    evts = [flow(seconds=i * 2, dport=1000 + i, syn=2, ack=0) for i in range(15)]
    evts += [flow(seconds=600 + i * 2, dport=2000 + i, syn=2, ack=0) for i in range(15)]
    assert len(check_equivalent(evts)) == 2


def test_multi_source_interleave_equivalent():
    evts = []
    for i in range(40):
        evts.append(flow(seconds=i * 3, sip="10.9.0.1", dport=1000 + (i % 20), syn=2, ack=0))
        evts.append(flow(seconds=i * 3 + 1, sip="10.9.0.2", dport=2000 + i, syn=2, ack=0))
    check_equivalent(evts)


def test_duplicate_ports_equivalent():
    evts = [flow(seconds=i * 2, dport=1000 + (i % 8), syn=2, ack=0) for i in range(40)]
    assert check_equivalent(evts) == []


def test_randomized_equivalent():
    import random

    rng = random.Random(20260928)
    for _ in range(4):
        evts = []
        for _ in range(rng.randint(10, 80)):
            evts.append(flow(seconds=rng.randint(0, 600), dport=rng.choice([80, 443] + list(range(2000, 2030))),
                             syn=rng.choice([0, 1, 3]), ack=rng.choice([0, 1])))
        check_equivalent(evts)


def test_shuffled_equivalent():
    import random

    evts = [flow(seconds=i * 2, dport=1000 + i, syn=2, ack=0) for i in range(30)]
    check_equivalent(evts)
    rng = random.Random(9)
    shuffled = list(evts)
    rng.shuffle(shuffled)
    check_equivalent(shuffled)


def test_chunk_boundary_equivalent():
    import csv
    import shutil
    import tempfile
    from pathlib import Path as _Path

    from app.services.datasets.cse_cic_ids2018 import CseCicIds2018Adapter
    from app.services.datasets.evaluate import chunked_detect

    cols = ["Dst Port", "Protocol", "Timestamp", "Flow Duration", "Tot Fwd Pkts",
            "Tot Bwd Pkts", "TotLen Fwd Pkts", "TotLen Bwd Pkts", "Label", "Src IP",
            "SYN Flag Cnt", "ACK Flag Cnt"]
    scratch = _Path(tempfile.mkdtemp(prefix="esf-f003-chunk-"))
    try:
        target = scratch / "scan.csv"
        with target.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=cols)
            writer.writeheader()
            for i in range(30):
                writer.writerow({"Dst Port": str(1000 + i), "Protocol": "6",
                                 "Timestamp": f"14/02/2018 08:00:{i:02d}",
                                 "Flow Duration": "100", "Tot Fwd Pkts": "2",
                                 "Tot Bwd Pkts": "0", "TotLen Fwd Pkts": "120",
                                 "TotLen Bwd Pkts": "0", "Label": "Benign",
                                 "Src IP": "10.9.9.9",
                                 "SYN Flag Cnt": "3", "ACK Flag Cnt": "1"})
        from app.services.detect.flow.config import FlowConfig as _CFG

        adapter = CseCicIds2018Adapter()
        dets = chunked_detect(adapter, target, target.name, _CFG(),
                              chunk_rows=10, overlap_minutes=40, order="time")
        scans = [d for d in dets if d.rule_id == "FLOW-003"]
        events = []
        for n, raw in adapter.iter_rows(target):
            result = adapter.normalize_row(raw, source_file=target.name, source_row=n)
            assert result.ok and result.event is not None
            events.append(result.event)
        direct = [d for d in PortScan(_CFG()).evaluate(prepare(events))
                  if d.rule_name == "Port-Scan-like Behavior"]
        # 30 rapid distinct-port flows fire twice (rows 1-15, rows 16-30);
        # chunked streaming must find the same two detections.
        assert len(direct) == 2
        assert len(scans) == 2
        assert {d.fingerprint for d in scans} == {d.fingerprint for d in direct}
        assert {d.fingerprint: d.bucket_event_ids for d in scans} == \
            {d.fingerprint: d.bucket_event_ids for d in direct}
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def test_perf_small_dense(capsys):
    import time

    from app.services.detect.flow.rules import _pairs

    # Dense but never firing (10 distinct ports): windows grow unbounded,
    # exposing the rebuild cost without detection noise.
    def build(n):
        return [flow(seconds=(i * 240 // n), dport=1000 + (i % 10), syn=2, ack=0)
                for i in range(n)]

    rule = PortScan(CFG)
    small, big = build(4000), build(8000)
    t0 = time.perf_counter()
    reference_scan(rule, _pairs(prepare(small)))
    ref_small = time.perf_counter() - t0
    t0 = time.perf_counter()
    reference_scan(rule, _pairs(prepare(big)))
    ref_big = time.perf_counter() - t0
    t0 = time.perf_counter()
    opt_small = optimized(rule, small)
    t_small = time.perf_counter() - t0
    t0 = time.perf_counter()
    opt_big = optimized(rule, big)
    t_big = time.perf_counter() - t0
    assert dumped(opt_small) == dumped(reference_scan(rule, _pairs(prepare(small))))
    assert dumped(opt_big) == dumped(reference_scan(rule, _pairs(prepare(big))))
    print(f"\nFLOW-003 perf: ref {ref_small:.2f}s->{ref_big:.2f}s, "
          f"opt {t_small:.2f}s->{t_big:.2f}s rows=4000/8000")
    assert ref_big > 2.5 * ref_small  # quadratic signature
    assert t_big < ref_big / 3  # optimized substantially faster at scale
    assert t_big < 5.0
