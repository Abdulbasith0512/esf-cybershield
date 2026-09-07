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
    evts += [flow(seconds=7200 + i * 60, proto="UDP", dport=4443) for i in range(6)]
    dets = run("FLOW-005", evts)
    assert len(dets) == 1
    d = dets[0]
    assert d.severity == "LOW" and d.confidence == 0.5
    assert len(d.evidence_event_ids) == 5


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
