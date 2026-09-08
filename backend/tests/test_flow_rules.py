"""Per-rule unit tests for FLOW-001..FLOW-006. Pure functions over dicts."""

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.services.detect.flow import default_flow_rules, detect_flows  # noqa: E402
from app.services.detect.flow.config import FlowConfig  # noqa: E402

T0 = datetime(2026, 9, 3, 9, 0, 0, tzinfo=timezone.utc)
_n = 0


def flow(seconds=0, dip="10.0.0.9", sip=None, dport=443, proto="TCP",
         syn=1, ack=1, fwd=1000, bwd=800, byts=5000, pkts=10.0, flow_extra=None, **kw):
    """One network_connection event with CIC-style flow telemetry."""
    global _n
    _n += 1
    flow_block = {
        "Flow Duration": 1000, "Tot Fwd Pkts": 5, "Tot Bwd Pkts": 5,
        "TotLen Fwd Pkts": fwd, "TotLen Bwd Pkts": bwd,
        "Flow Byts/s": byts, "Flow Pkts/s": pkts,
        "SYN Flag Cnt": syn, "ACK Flag Cnt": ack, "RST Flag Cnt": 0,
        "Fwd Header Len": 20, "Bwd Header Len": 20}
    flow_block.update(flow_extra or {})
    e = {"event_id": f"evt-f{_n:05d}", "timestamp": (T0 + timedelta(seconds=seconds)).isoformat(),
         "event_type": "network_connection", "source": "cse_cic_ids2018",
         "host": None, "user": None, "source_ip": sip, "destination_ip": dip,
         "destination_port": dport, "protocol": proto,
         "bytes_sent": fwd, "bytes_received": bwd, "status": None,
         "raw_event": {"flow": flow_block}}
    e.update(kw)
    return e


def run(rule_id, events, config=None):
    config = config or FlowConfig()
    rules = [r for r in default_flow_rules(config) if r.rule_id == rule_id]
    return detect_flows(events, config=config, rules=rules)


# ---------------- FLOW-001 ----------------

def test_flow001_fires():
    evts = [flow(seconds=i) for i in range(55)]
    dets = run("FLOW-001", evts)
    assert len(dets) == 1
    d = dets[0]
    assert d.rule_id == "FLOW-001" and d.severity == "MEDIUM"
    assert len(d.evidence_event_ids) == 20
    assert d.metadata["count"] == 55


def test_flow001_below_threshold():
    assert run("FLOW-001", [flow(seconds=i) for i in range(30)]) == []


def test_flow001_global_fallback():
    evts = [flow(seconds=i, dip=None) for i in range(55)]
    dets = run("FLOW-001", evts)
    assert len(dets) == 1 and dets[0].metadata["key"] == "GLOBAL"


# ---------------- FLOW-002 ----------------

def test_flow002_fires():
    evts = [flow(seconds=i * 10, syn=3, ack=1, fwd=200, bwd=100) for i in range(22)]
    dets = run("FLOW-002", evts)
    assert len(dets) == 1
    assert dets[0].severity == "HIGH"
    assert len(dets[0].evidence_event_ids) == 20


def test_flow002_below_threshold():
    evts = [flow(seconds=i * 10, syn=3, ack=1, fwd=200, bwd=100) for i in range(10)]
    assert run("FLOW-002", evts) == []


def test_flow002_nonqualifying_silent():
    # Balanced flags and large transfers are not brute-force-like.
    evts = [flow(seconds=i * 10, syn=1, ack=1, fwd=50000, bwd=40000) for i in range(25)]
    assert run("FLOW-002", evts) == []


# ---------------- FLOW-003 ----------------

def test_flow003_fires():
    evts = [flow(seconds=i * 10, sip="10.1.2.3", dport=1000 + i) for i in range(16)]
    dets = run("FLOW-003", evts)
    scans = [d for d in dets if d.rule_name == "Port-Scan-like Behavior"]
    assert len(scans) == 1
    # Fires as soon as the 15th distinct port appears: 15 evidence IDs.
    assert len(scans[0].evidence_event_ids) == 15
    assert scans[0].metadata["distinct_ports"] == 15


def test_flow003_below_threshold():
    evts = [flow(seconds=i * 10, sip="10.1.2.3", dport=1000 + i) for i in range(8)]
    assert [d for d in run("FLOW-003", evts) if d.rule_name == "Port-Scan-like Behavior"] == []


def test_flow003_requires_source_ip():
    # No source_ip anywhere: scan mode silent, entropy fallback labeled honestly.
    evts = [flow(seconds=i * 2, dport=1000 + (i % 30)) for i in range(60)]
    dets = run("FLOW-003", evts)
    assert all(d.rule_name == "Port Entropy Anomaly" for d in dets)
    assert all("entropy" in d.reason for d in dets)


# ---------------- FLOW-004 ----------------

def _baseline_traffic(start_sec, count, byts=20000):
    return [flow(seconds=start_sec + i * 30, byts=byts) for i in range(count)]


def test_flow004_fires():
    evts = _baseline_traffic(0, 12)  # 6 buckets of history
    evts += [flow(seconds=600 + i * 10, byts=50_000_000) for i in range(3)]
    dets = run("FLOW-004", evts)
    assert len(dets) == 1
    assert len(dets[0].evidence_event_ids) == 3


def test_flow004_below_threshold():
    assert run("FLOW-004", _baseline_traffic(0, 12)) == []


def test_flow004_needs_history():
    assert run("FLOW-004", [flow(seconds=i * 10, byts=50_000_000) for i in range(3)]) == []


# ---------------- FLOW-005 ----------------

def test_flow005_fires():
    evts = [flow(seconds=i * 60) for i in range(30)]
    evts += [flow(seconds=7200 + i, proto="UDP", dport=4443) for i in range(60)]
    dets = run("FLOW-005", evts)
    assert len(dets) == 1
    d = dets[0]
    assert d.severity == "LOW" and d.confidence == 0.5
    assert len(d.evidence_event_ids) == 5
    assert d.metadata["peak_minute_count"] == 60


def test_flow005_sparse_novelty_silent():
    # Novel but sparse (one flow per minute): novelty alone never fires.
    evts = [flow(seconds=i * 60) for i in range(30)]
    evts += [flow(seconds=7200 + i * 60, proto="UDP", dport=4443) for i in range(6)]
    assert run("FLOW-005", evts) == []


def test_flow005_ephemeral_trivial_silent():
    evts = [flow(seconds=i * 60) for i in range(30)]
    evts += [flow(seconds=7200 + i * 60, proto="TCP", dport=50000) for i in range(6)]
    assert run("FLOW-005", evts) == []


def test_flow005_ephemeral_dense_fires():
    evts = [flow(seconds=i * 60) for i in range(30)]
    evts += [flow(seconds=7200 + i, proto="TCP", dport=50000) for i in range(60)]
    (d,) = run("FLOW-005", evts)
    assert d.metadata["ephemeral_port"] is True
    assert d.metadata["peak_minute_count"] == 60
    assert len(d.bucket_event_ids) == 60 and len(d.evidence_event_ids) == 5


def test_flow005_known_service_dense_fires():
    evts = [flow(seconds=i * 60) for i in range(30)]
    evts += [flow(seconds=7200 + i, proto="TCP", dport=8443) for i in range(60)]
    (d,) = run("FLOW-005", evts)
    assert d.metadata["ephemeral_port"] is False
    assert (d.metadata["protocol"], d.metadata["destination_port"]) == ("TCP", 8443)


def test_flow005_known_pair_dense_silent():
    evts = [flow(seconds=i * 60) for i in range(30)]
    evts += [flow(seconds=7200 + i) for i in range(60)]  # known TCP/443
    assert run("FLOW-005", evts) == []


def test_flow005_peak_boundary():
    base = [flow(seconds=i * 60) for i in range(30)]
    assert len(run("FLOW-005", base + [flow(seconds=7200 + i, proto="UDP", dport=4443)
                                       for i in range(50)])) == 1
    assert run("FLOW-005", base + [flow(seconds=7200 + i, proto="UDP", dport=4444)
                                   for i in range(49)]) == []


def test_flow005_order_independent():
    import random  # noqa: E402

    evts = [flow(seconds=i * 60) for i in range(30)]
    evts += [flow(seconds=7200 + i, proto="UDP", dport=4443) for i in range(60)]
    first = [d.model_dump(mode="json") for d in run("FLOW-005", evts)]
    rng = random.Random(18)
    shuffled = list(evts)
    rng.shuffle(shuffled)
    assert [d.model_dump(mode="json") for d in run("FLOW-005", shuffled)] == first


def test_flow005_no_label_params():
    import inspect  # noqa: E402

    from app.services.detect.flow.rules import ProtocolPortNovelty  # noqa: E402

    params = inspect.signature(ProtocolPortNovelty.evaluate).parameters
    assert not [p for p in params if "label" in p]


def test_flow005_known_pair_silent():
    assert run("FLOW-005", [flow(seconds=i * 60) for i in range(30)]) == []


# ---------------- FLOW-006 ----------------

def _burst(seconds_base, count, pkts_each=200):
    return [flow(seconds=seconds_base + (i % 25),
                 flow_extra={"Tot Fwd Pkts": pkts_each, "Tot Bwd Pkts": 0,
                             "Flow Pkts/s": float(pkts_each)})
            for i in range(count)]


def test_flow006_fires():
    # 600 flows x 200 pkts in 25 s -> 4800 pps... need >= 50k pps.
    evts = _burst(0, 600, pkts_each=3000)
    dets = run("FLOW-006", evts)
    assert len(dets) == 1
    assert dets[0].severity == "HIGH"
    assert len(dets[0].evidence_event_ids) == 20


def test_flow006_below_threshold():
    assert run("FLOW-006", _burst(0, 100, pkts_each=3000)) == []


def test_flow006_needs_rate_not_just_count():
    # Many flows but trickling packets: count ok, rate not.
    assert run("FLOW-006", _burst(0, 600, pkts_each=2)) == []


# ---------------- bucket_event_ids ----------------
# Complete label-free contributor sets; evidence caps unchanged.

def test_bucket_001_full_vs_capped():
    (d,) = run("FLOW-001", [flow(seconds=i) for i in range(55)])
    assert len(d.evidence_event_ids) == 20
    assert len(d.bucket_event_ids) == 55
    assert set(d.evidence_event_ids) <= set(d.bucket_event_ids)
    assert d.bucket_event_ids == sorted(set(d.bucket_event_ids))


def test_bucket_002_fire_and_clear():
    evts = []
    for burst in range(3):
        base = burst * 1200
        evts += [flow(seconds=base + i * 5, syn=3, ack=1, fwd=200, bwd=100)
                 for i in range(25)]
    dets = run("FLOW-002", evts)
    assert len(dets) == 3
    buckets = [set(d.bucket_event_ids) for d in dets]
    for d, bucket in zip(dets, buckets):
        assert len(d.bucket_event_ids) == 20 == len(d.evidence_event_ids)
    assert len(set().union(*buckets)) == 60  # disjoint first-20 per burst


def test_bucket_003_scan_complete():
    evts = [flow(seconds=i * 10, sip="10.1.2.3", dport=1000 + i) for i in range(16)]
    dets = run("FLOW-003", evts)
    scans = [d for d in dets if d.rule_name == "Port-Scan-like Behavior"]
    assert len(scans) == 1
    # Fires at the 15th distinct port and resets, so the window holds 15.
    assert len(scans[0].bucket_event_ids) == 15
    assert set(scans[0].evidence_event_ids) == set(scans[0].bucket_event_ids)


def test_bucket_003_fallback_exceeds_cap():
    evts = [flow(seconds=i * 2, dport=1000 + (i % 30)) for i in range(60)]
    dets = run("FLOW-003", evts)
    assert dets and all(d.rule_name == "Port Entropy Anomaly" for d in dets)
    assert all(len(d.evidence_event_ids) <= 20 for d in dets)
    assert any(len(d.bucket_event_ids) > 20 for d in dets)
    for d in dets:
        assert set(d.evidence_event_ids) <= set(d.bucket_event_ids)


def test_bucket_004_exceeds_cap3():
    evts = _baseline_traffic(0, 12)
    evts += [flow(seconds=600 + i * 10, byts=50_000_000) for i in range(6)]
    (d,) = run("FLOW-004", evts)
    assert len(d.evidence_event_ids) == 3
    assert len(d.bucket_event_ids) == 6


def test_bucket_005_exceeds_cap5():
    evts = [flow(seconds=i * 60) for i in range(30)]
    evts += [flow(seconds=7200 + i, proto="UDP", dport=4443) for i in range(60)]
    (d,) = run("FLOW-005", evts)
    assert len(d.evidence_event_ids) == 5
    assert len(d.bucket_event_ids) == 60


def test_bucket_006_full():
    (d,) = run("FLOW-006", _burst(0, 600, pkts_each=3000))
    assert len(d.evidence_event_ids) == 20
    assert len(d.bucket_event_ids) == 600


def test_fingerprint_ignores_bucket():
    from app.services.detect.common import prepare  # noqa: E402
    from app.services.detect.models import make_result  # noqa: E402

    evts = prepare([flow(seconds=i) for i in range(25)])
    ev, full = evts[:20], evts
    base = make_result("FLOW-001", "n", "MEDIUM", 0.5, "r", ev, {})
    same = make_result("FLOW-001", "n", "MEDIUM", 0.5, "r", ev, {}, bucket=full)
    assert (same.fingerprint, same.detection_id) == (base.fingerprint, base.detection_id)
    assert len(same.bucket_event_ids) == 25 and base.bucket_event_ids == []
    other = make_result("FLOW-001", "n", "MEDIUM", 0.5, "r", evts[:19], {}, bucket=full)
    assert other.fingerprint != base.fingerprint


def test_bucket_deterministic_and_shuffle_invariant():
    import random  # noqa: E402

    evts = [flow(seconds=i) for i in range(55)]
    first = [d.model_dump(mode="json") for d in run("FLOW-001", evts)]
    assert [d.model_dump(mode="json") for d in run("FLOW-001", list(evts))] == first
    rng = random.Random(11)
    shuffled = list(evts)
    rng.shuffle(shuffled)
    assert [d.model_dump(mode="json") for d in run("FLOW-001", shuffled)] == first


def test_bucket_label_isolation():
    import ast  # noqa: E402

    models = (BACKEND / "app" / "services" / "detect" / "models.py").read_text(encoding="utf-8")
    for banned in ("Label", "evaluation_only", "raw_event"):
        assert banned not in models, banned
    rules = (BACKEND / "app" / "services" / "detect" / "flow" / "rules.py").read_text(encoding="utf-8")
    for line in rules.splitlines():
        if "bucket" in line:
            assert "evaluation_only" not in line and "Label" not in line, line
    tree = ast.parse(models)
    assert not [n for n in ast.walk(tree)
                if isinstance(n, ast.Attribute) and n.attr == "evaluation_only"]
