"""FLOW-002 optimization equivalence: frozen reference vs incremental.

The REFERENCE_EVALUATE function below is a verbatim frozen copy of the
pre-optimization RepeatedAttempts.evaluate (O(n*w) rescan). DO NOT MODIFY it;
it exists solely to prove the optimized implementation is behaviorally
identical. If the rule's intended semantics ever change, update the reference
first in a separate review, then re-optimize.
"""

import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.services.detect.flow.config import FlowConfig  # noqa: E402
from app.services.detect.flow.rules import (  # noqa: E402
    GLOBAL,
    RepeatedAttempts,
    _bounded,
    _entity_key,
    _pairs,
)
from app.services.detect.models import make_result  # noqa: E402

T0 = datetime(2026, 9, 3, 9, 0, 0, tzinfo=timezone.utc)
_n = 0
CFG = FlowConfig()


def flow(seconds=0, dip="10.0.0.9", dport=22, syn=3, ack=1, fwd=200, bwd=100,
         byts=5000, pkts=10.0, **kw):
    """One network_connection event with CIC-style flow telemetry."""
    global _n
    _n += 1
    e = {"event_id": f"evt-o{_n:05d}", "timestamp": (T0 + timedelta(seconds=seconds)).isoformat(),
         "event_type": "network_connection", "source": "cse_cic_ids2018",
         "host": None, "user": None, "source_ip": None, "destination_ip": dip,
         "destination_port": dport, "protocol": "TCP",
         "bytes_sent": fwd, "bytes_received": bwd, "status": None,
         "raw_event": {"flow": {
             "Flow Duration": 1000, "Tot Fwd Pkts": 5, "Tot Bwd Pkts": 5,
             "TotLen Fwd Pkts": fwd, "TotLen Bwd Pkts": bwd,
             "Flow Byts/s": byts, "Flow Pkts/s": pkts,
             "SYN Flag Cnt": syn, "ACK Flag Cnt": ack, "RST Flag Cnt": 0,
             "Fwd Header Len": 20, "Bwd Header Len": 20}}}
    e.update(kw)
    return e


def reference_evaluate(rule, events):
    """FROZEN reference: pre-optimization O(n*w) rescan. DO NOT MODIFY."""
    from datetime import timedelta as _td

    from app.services.detect.common import prepare as _prepare

    events = _prepare(events)
    groups: dict[str, list] = {}
    for v, r in _pairs(events):
        port = v.destination_port
        groups.setdefault(_entity_key(v.destination_ip or GLOBAL,
                                      str(port) if port is not None else "?"),
                          []).append((v, r))
    out = []
    window = _td(minutes=rule.config.brute_window_minutes)
    for key, members in groups.items():
        members.sort(key=lambda t: (t[0].ts, t[0].event_id))
        start = 0
        for end in range(len(members)):
            while members[end][0].ts - members[start][0].ts >= window:
                start += 1
            windowed = members[start:end + 1]
            qualifying = [(v, r) for v, r in windowed if rule._qualifying(v)]
            if len(qualifying) >= rule.config.brute_min_flows:
                qualifying.sort(key=lambda t: (t[0].ts, t[0].event_id))
                n = len(qualifying)
                rows = [r for _, r in qualifying]
                out.append(make_result(
                    rule.rule_id, rule.name, rule.severity,
                    min(0.60 + 0.02 * n, 0.9),
                    (f"Repeated connection attempts detected: {n} short SYN-heavy "
                     f"flows to {key} within 5 minutes."),
                    _bounded(rows),
                    {"key": key, "qualifying_count": n,
                     "window_count": len(windowed)}))
                start = end + 1
    return out


def optimized(rule, events):
    from app.services.detect.common import prepare

    return rule.evaluate(prepare(events))


def dumped(dets):
    return [(d.detection_id, d.rule_id, d.rule_name, d.severity, d.confidence,
             d.reason, d.evidence_event_ids, d.first_seen.isoformat(),
             d.last_seen.isoformat(), d.metadata) for d in dets]


def check_equivalent(events, rule=None):
    rule = rule or RepeatedAttempts(CFG)
    expected = dumped(reference_evaluate(rule, events))
    actual = dumped(optimized(rule, events))
    assert actual == expected


# A. small hand-controlled fixture: burst then quiet
def test_small_burst_equivalent():
    evts = [flow(seconds=i * 10, syn=3, ack=1, fwd=200, bwd=100) for i in range(25)]
    evts += [flow(seconds=3600 + i * 60, syn=1, ack=1, fwd=50000, bwd=40000) for i in range(5)]
    check_equivalent(evts)


# B. threshold boundary: exactly at window, count, and byte edges
def test_threshold_boundary():
    evts = [flow(seconds=i * 10, syn=3, ack=1, fwd=200, bwd=100) for i in range(19)]
    check_equivalent(evts)  # below threshold: no detections either way
    evts.append(flow(seconds=190, syn=3, ack=1, fwd=200, bwd=100))
    check_equivalent(evts)  # exactly 20: fires identically


# C. below threshold
def test_below_threshold():
    check_equivalent([flow(seconds=i * 10) for i in range(10)])


# D. exactly 20 qualifying flows
def test_exactly_twenty():
    check_equivalent([flow(seconds=i * 5, syn=4, ack=0, fwd=100, bwd=50) for i in range(20)])


# E. 21+ qualifying flows (evidence bounding kicks in past 20)
def test_twenty_one_plus():
    check_equivalent([flow(seconds=i * 5, syn=4, ack=0, fwd=100, bwd=50) for i in range(35)])


# F. events entering and leaving the window across multiple firings
def test_enter_leave_multiple_firings():
    evts = []
    for burst in range(3):
        base = burst * 1200
        evts += [flow(seconds=base + i * 5, syn=3, ack=1, fwd=200, bwd=100) for i in range(25)]
    check_equivalent(evts)


# G. multiple aggregation keys interleave
def test_multiple_keys():
    evts = []
    for i in range(30):
        evts.append(flow(seconds=i * 7, dip="10.0.0.9", dport=22))
        evts.append(flow(seconds=i * 7 + 3, dip="10.0.0.10", dport=2222,
                         syn=1, ack=1, fwd=60000, bwd=50000))
    check_equivalent(evts)


# H. mixed qualifying and non-qualifying flows
def test_mixed_qualifying():
    evts = []
    for i in range(40):
        if i % 2 == 0:
            evts.append(flow(seconds=i * 6, syn=5, ack=1, fwd=300, bwd=100))
        else:
            evts.append(flow(seconds=i * 6, syn=1, ack=1, fwd=90000, bwd=80000))
    check_equivalent(evts)


# I. equal timestamps (tie-break by event_id)
def test_equal_timestamps():
    check_equivalent([flow(seconds=0, syn=3, ack=1, fwd=200, bwd=100) for _ in range(25)])


# J. boundary timestamp at exactly 5 minutes
def test_exact_window_boundary():
    evts = [flow(seconds=0, syn=3, ack=1, fwd=200, bwd=100) for _ in range(10)]
    evts += [flow(seconds=300, syn=3, ack=1, fwd=200, bwd=100) for _ in range(10)]
    check_equivalent(evts)  # 300 s apart: exclusive end keeps them separate


# K. duplicate-looking flows with different event IDs
def test_duplicate_looking_flows():
    base = flow(seconds=42, syn=3, ack=1, fwd=200, bwd=100)
    evts = []
    for i in range(22):
        clone = dict(base, raw_event=dict(base["raw_event"]))
        clone["event_id"] = f"evt-dup-{i:03d}"
        evts.append(clone)
    check_equivalent(evts)


# L. randomized deterministic fixtures
def test_randomized_fixtures():
    import random

    rng = random.Random(20260903)
    for trial in range(5):
        evts = []
        for i in range(rng.randint(5, 60)):
            evts.append(flow(
                seconds=rng.randint(0, 900),
                dip=rng.choice(["10.0.0.9", "10.0.0.10", None]),
                dport=rng.choice([22, 22, 80, 443]),
                syn=rng.randint(0, 5), ack=rng.randint(0, 5),
                fwd=rng.choice([200, 50000]), bwd=rng.choice([100, 40000])))
        check_equivalent(evts)


# M. reversed and shuffled input
def test_shuffled_input():
    import random

    evts = [flow(seconds=i * 5, syn=3, ack=1, fwd=200, bwd=100) for i in range(30)]
    evts += [flow(seconds=2000 + i * 30, dip="10.0.0.11", dport=80) for i in range(8)]
    check_equivalent(evts)
    rng = random.Random(7)
    shuffled = list(evts)
    rng.shuffle(shuffled)
    check_equivalent(shuffled)
    assert dumped(optimized(RepeatedAttempts(CFG), evts)) == \
        dumped(optimized(RepeatedAttempts(CFG), list(reversed(evts))))


def test_perf_reference_vs_optimized(capsys):
    import time

    # Dense sub-threshold traffic: thousands of events inside 5-minute windows
    # without ever firing, so the reference rescans the full window on every
    # event while the incremental version touches each event once.
    evts = [flow(seconds=i * 0.04, syn=1, ack=1, fwd=200, bwd=100) for i in range(3000)]
    rule = RepeatedAttempts(CFG)
    t0 = time.perf_counter()
    ref = reference_evaluate(rule, evts)
    t_ref = time.perf_counter() - t0
    t0 = time.perf_counter()
    opt = optimized(rule, evts)
    t_opt = time.perf_counter() - t0
    assert dumped(opt) == dumped(ref)
    speedup = t_ref / max(t_opt, 1e-9)
    print(f"\nFLOW-002 perf: reference={t_ref:.2f}s optimized={t_opt:.2f}s speedup={speedup:.1f}x "
          f"rows={len(evts)} detections={len(opt)}")
    assert t_opt < t_ref
