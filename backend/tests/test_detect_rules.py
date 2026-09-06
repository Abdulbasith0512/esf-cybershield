"""Per-rule unit tests. Pure functions over dicts — no DB, no API."""

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.services.detect.config import DetectorConfig  # noqa: E402
from app.services.detect.engine import detect  # noqa: E402
from app.services.detect.rules import default_rules  # noqa: E402

T0 = datetime(2026, 9, 3, 9, 0, 0, tzinfo=timezone.utc)
_n = 0


def evt(event_type="authentication", status="success", user="alice",
        host="WIN-001", ip="10.0.0.1", seconds=0, **kw):
    global _n
    _n += 1
    e = {"event_id": f"evt-t{_n:04d}", "timestamp": (T0 + timedelta(seconds=seconds)).isoformat(),
         "event_type": event_type, "source": "windows", "host": host, "user": user,
         "source_ip": ip, "status": status,
         "raw_event": {"generator": "test", "synthetic": True,
                       "scenario_id": "unit", "scenario_type": "unit"}}
    e.update(kw)
    return e


def run(rule_id, events, config=None):
    config = config or DetectorConfig()
    rules = [r for r in default_rules(config) if r.rule_id == rule_id]
    return detect(events, config=config, rules=rules)


# ---------------- AUTH-001 ----------------

def test_auth001_fires():
    evts = [evt(status="failed", seconds=i * 20) for i in range(3)]
    evts.append(evt(status="success", seconds=200))
    dets = run("AUTH-001", evts)
    assert len(dets) == 1
    d = dets[0]
    assert d.rule_id == "AUTH-001" and d.severity == "HIGH"
    assert len(d.evidence_event_ids) == 4


def test_auth001_below_threshold():
    evts = [evt(status="failed", seconds=i * 20) for i in range(2)]
    evts.append(evt(status="success", seconds=200))
    assert run("AUTH-001", evts) == []


def test_auth001_outside_window():
    evts = [evt(status="failed", seconds=i * 20) for i in range(3)]
    evts.append(evt(status="success", seconds=3600))
    assert run("AUTH-001", evts) == []


def test_auth001_user_isolation():
    evts = [evt(status="failed", user="bob", seconds=i * 20) for i in range(3)]
    evts.append(evt(status="success", user="alice", seconds=200))
    assert run("AUTH-001", evts) == []


def test_auth001_out_of_order_same_result():
    evts = [evt(status="failed", seconds=i * 20) for i in range(3)]
    evts.append(evt(status="success", seconds=200))
    fwd = [d.fingerprint for d in run("AUTH-001", evts)]
    back = [d.fingerprint for d in run("AUTH-001", list(reversed(evts)))]
    assert fwd == back


def test_auth001_host_fallback_no_ip():
    evts = [evt(status="failed", ip=None, seconds=i * 20) for i in range(3)]
    evts.append(evt(status="success", ip=None, seconds=200))
    dets = run("AUTH-001", evts)
    assert len(dets) == 1


# ---------------- PROC-001 ----------------

def test_proc001_shell_from_service():
    dets = run("PROC-001", [evt(
        event_type="process_creation", source="endpoint", status="started",
        process_name="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        parent_process="C:\\Windows\\System32\\svchost.exe",
        command_line="powershell.exe -NoProfile -File .\\inventory.ps1")])
    assert len(dets) == 1 and dets[0].severity == "HIGH"


def test_proc001_benign_no_fire():
    assert run("PROC-001", [evt(
        event_type="process_creation", source="endpoint", status="started",
        process_name="C:\\Program Files\\Outlook\\outlook.exe",
        parent_process="C:\\Windows\\explorer.exe",
        command_line="/recycle")]) == []


# ---------------- AUTH-002 ----------------

def test_auth002_day_ok_night_fires():
    day = evt(timestamp=(T0.replace(hour=10)).isoformat())
    night = evt(timestamp=(T0.replace(hour=3, minute=22)).isoformat())
    assert run("AUTH-002", [day]) == []
    dets = run("AUTH-002", [night])
    assert len(dets) == 1 and dets[0].severity == "MEDIUM"
    assert "03:22" in dets[0].reason


# ---------------- NET-001 ----------------

def test_net001_ioc_hit_and_miss():
    hit = evt(event_type="network_connection", source="firewall", status="allowed",
              destination_ip="203.0.113.200", destination_port=443, protocol="TCP")
    miss = evt(event_type="network_connection", source="firewall", status="allowed",
               destination_ip="10.0.0.9", destination_port=443, protocol="TCP")
    dets = run("NET-001", [hit])
    assert len(dets) == 1
    assert dets[0].metadata["matched_ioc"]["indicator"] == "203.0.113.200"
    assert run("NET-001", [miss]) == []


# ---------------- DATA-001 ----------------

def test_data001_threshold():
    big = evt(event_type="data_transfer", source="firewall", status="completed",
              destination_ip="203.0.113.200", bytes_sent=4 * 1024**3)
    small = evt(event_type="data_transfer", source="firewall", status="completed",
                destination_ip="10.0.0.9", bytes_sent=80 * 1024**2)
    assert len(run("DATA-001", [big])) == 1
    assert run("DATA-001", [small]) == []


# ---------------- NET-002 ----------------

def test_net002_volume():
    base = T0.replace(hour=12)
    evts = [evt(event_type="dns_query", source="dns", status="resolved",
                domain="intranet.local", destination_ip="10.10.0.53",
                timestamp=(base + timedelta(seconds=i * 2)).isoformat())
            for i in range(101)]
    dets = run("NET-002", evts)
    assert len(dets) == 1 and "High-volume DNS" in dets[0].reason
    assert run("NET-002", evts[:50]) == []


# ---------------- AUTH-003 ----------------

def test_auth003_new_ip():
    evts = [evt(ip="10.0.0.1", seconds=i * 60) for i in range(3)]
    evts.append(evt(ip="10.0.0.9", seconds=300))
    dets = run("AUTH-003", evts)
    assert len(dets) == 1 and dets[0].metadata["new_ip"] == "10.0.0.9"
    assert run("AUTH-003", evts[:3]) == []


# ---------------- PROC-002 ----------------

def test_proc002_pair_and_benign():
    sus = evt(event_type="process_creation", source="endpoint", status="started",
              process_name="powershell.exe", parent_process="services.exe")
    benign = evt(event_type="process_creation", source="endpoint", status="started",
                 process_name="outlook.exe", parent_process="explorer.exe")
    dets = run("PROC-002", [sus])
    assert len(dets) == 1
    assert dets[0].metadata == {"parent": "services.exe", "child": "powershell.exe"}
    assert run("PROC-002", [benign]) == []
