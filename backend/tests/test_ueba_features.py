"""UEBA feature-builder tests. Pure functions over dicts — no DB, no model."""

import shutil
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.services.ueba.baseline import assess  # noqa: E402
from app.services.ueba.config import UebaConfig  # noqa: E402
from app.services.ueba.features import build_observations  # noqa: E402

CFG = UebaConfig()
T0 = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)
_n = 0


@pytest.fixture()
def scratch_dir():
    d = Path(tempfile.mkdtemp(prefix="esf-ueba-"))
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


def evt(user="alice", host="WIN-001", ip="10.0.0.1", minutes=0,
        event_type="authentication", status="success", **kw):
    global _n
    _n += 1
    e = {"event_id": f"evt-u{_n:05d}",
         "timestamp": (T0 + timedelta(minutes=minutes)).isoformat(),
         "event_type": event_type, "source": "windows", "host": host,
         "user": user, "source_ip": ip, "status": status,
         "raw_event": {"generator": "test", "synthetic": True,
                       "scenario_id": "unit", "scenario_type": "unit"}}
    e.update(kw)
    return e


def test_expected_numeric_features():
    obs = build_observations(
        [evt(minutes=i * 5) for i in range(4)]
        + [evt(minutes=65, status="failed"), evt(minutes=70, status="failed")], CFG)
    assert len(obs) == 2
    f = obs[0]["features"]
    assert f["event_count"] == 4 and f["failed_auth_count"] == 0
    assert f["failed_auth_ratio"] == 0.0
    g = obs[1]["features"]
    assert g["failed_auth_count"] == 2 and g["failed_auth_ratio"] == 1.0
    assert set(f) == set(CFG.feature_columns)  # stable documented columns


def test_no_ground_truth_features():
    obs = build_observations([evt()], CFG)
    cols = set(obs[0]["features"])
    assert not (cols & {"scenario_id", "scenario_type", "synthetic", "seed"})
    for forbidden in ("user_037", "WIN-001", "10.0.0.1", "evt-u"):
        assert forbidden not in cols
        for v in obs[0]["features"].values():
            assert not (isinstance(v, str) and forbidden in v)


def test_identifiers_group_only():
    a = build_observations([evt(user="alice", minutes=i) for i in range(3)]
                           + [evt(user="bob", minutes=i) for i in range(3)], CFG)
    assert {o["entity_key"] for o in a} == {"alice", "bob"}


def test_missing_telemetry_safe():
    evts = [evt(ip=None, minutes=0), evt(user=None, minutes=5),
            dict(evt(minutes=10), bytes_sent=None),
            evt(minutes=65, event_type="data_transfer", bytes_sent=5_000_000)]
    obs = build_observations(evts, CFG)
    assert obs  # no crash; user=None row excluded, Nones treated as zero/absent


def test_duplicates_deduped():
    e = evt(minutes=0)
    obs = build_observations([e, dict(e), evt(minutes=70)], CFG)
    total = sum(o["event_count"] for o in obs)
    assert total == 2


def test_out_of_order_identical():
    evts = [evt(minutes=m) for m in (0, 30, 65, 130, 5, 95)]
    a = build_observations(evts, CFG)
    b = build_observations(list(reversed(evts)), CFG)
    assert a == b


def test_cold_start_and_history():
    evts = [evt(minutes=i * 70) for i in range(8)]  # one per window-ish
    obs = build_observations(evts, CFG)
    st = assess(obs, CFG)
    first = st[f"alice|{obs[0]['window_start'].isoformat()}"]
    assert first["status"] == "COLD_START" and first["history_windows"] == 0
    later = st[f"alice|{obs[-1]['window_start'].isoformat()}"]
    assert later["history_windows"] == len(obs) - 1


def test_insufficient_history_flag():
    obs = build_observations([evt(minutes=i * 65) for i in range(2)], CFG)
    st = assess(obs, CFG)
    assert list(st.values())[1]["status"] == "INSUFFICIENT_HISTORY"


def test_ready_after_enough_history():
    cfg = UebaConfig(min_history_windows=2, min_history_events=2)
    obs = build_observations([evt(minutes=i * 65) for i in range(4)], cfg)
    st = assess(obs, cfg)
    assert list(st.values())[-1]["status"] == "READY"


def test_new_ip_causal_no_future_leak():
    # Second window introduces a new IP; first window must not see it.
    obs = build_observations([evt(minutes=0), evt(minutes=65, ip="10.0.0.9")], CFG)
    assert obs[0]["features"]["new_source_ip_count"] == 1  # cold window: all new
    assert obs[0]["features"]["unique_source_ip_count"] == 1
    assert obs[1]["features"]["unique_source_ip_count"] == 1


def test_no_ground_truth_in_ueba_code():
    import ast

    pkg = BACKEND / "app" / "services" / "ueba"
    targets = {"scenario_id", "scenario_type", "synthetic", "raw_event", "seed"}
    hits = []
    for path in pkg.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in targets:
                hits.append(f"{path.name}:{node.attr} (attribute)")
            elif isinstance(node, ast.Constant) and node.value in targets:
                hits.append(f"{path.name}:{node.value!r} (literal)")
    assert hits == [], f"ground-truth leakage: {hits}"


def test_feature_columns_match_config():
    assert len(CFG.feature_columns) == 12
    assert len(set(CFG.feature_columns)) == 12
