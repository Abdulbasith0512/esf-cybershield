"""Slice 7 tests: UEBA incident enrichment. Risk must never move."""

import sys
from datetime import datetime, timedelta
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.services.correlate.engine import correlate  # noqa: E402
from app.services.detect.common import coerce_ts  # noqa: E402
from app.services.mitre.enrich import enrich as mitre_enrich  # noqa: E402
from app.services.mitre.mapper import map_incident  # noqa: E402
from app.services.mitre.scorer import score_risk  # noqa: E402
from app.services.ueba.attach import attach_ueba  # noqa: E402
from app.services.ueba.config import UebaConfig  # noqa: E402
from app.services.ueba.features import build_observations  # noqa: E402
from app.services.ueba.model import UebaModel  # noqa: E402
from test_correlate_rules import CFG as CORR_CFG  # noqa: E402
from test_correlate_rules import devt  # noqa: E402

T0 = datetime(2026, 9, 3, 9, 0, 0)
_h = 0


def h(evt_type="authentication", user="alice", host="WIN-001", ip="10.0.0.1",
      minutes=0, status="success", **kw):
    """Raw event dict shaped like normalized telemetry."""
    global _h
    _h += 1
    e = {"event_id": f"evt-h{_h:05d}",
         "timestamp": (T0 + timedelta(minutes=minutes)).isoformat(),
         "event_type": evt_type, "source": "windows", "host": host,
         "user": user, "source_ip": ip, "status": status,
         "raw_event": {"generator": "test"}}
    e.update(kw)
    return e


def loud_user_events(user="mallory", base_min=0):
    """One loud hour (many auths + big transfer) plus quiet background."""
    evts = [h(user=user, minutes=base_min + i * 2) for i in range(3)]
    evts += [h(user=user, minutes=base_min + 40, event_type="data_transfer",
                source="firewall", status="completed",
                destination_ip="10.0.0.9", bytes_sent=3_000_000_000)]
    return evts


def background(users=("alice", "bob"), per=12):
    return [h(user=u, minutes=i * 65) for u in users for i in range(per)]


def fit_model(extra):
    obs = build_observations(background() + extra)
    return UebaModel(UebaConfig()).fit(obs)


def incident_for_dets(dets, by_id):
    inc = correlate(dets, events_by_id=by_id, config=CORR_CFG)[0]
    mp = {d.detection_id: d for d in dets}
    (enr,) = mitre_enrich([inc], mp)
    return enr, mp


def test_anomalous_available():
    evts = loud_user_events()
    by_id = {e["event_id"]: e for e in background() + evts}
    model = fit_model(evts)
    dets = [devt("AUTH-001", user="mallory", start_min=0,
                 evidence=[evts[0]["event_id"], evts[1]["event_id"]]),
            devt("DATA-001", user="mallory", start_min=40,
                 evidence=[evts[3]["event_id"]],
                 extra_meta={"bytes_sent": 3_000_000_000, "threshold": 1_000_000_000})]
    enr, mp = incident_for_dets(dets, by_id)
    (wrapped,) = attach_ueba([enr], by_id, model)
    u = wrapped.ueba
    assert u.available and u.anomaly_flag is True
    assert u.anomaly_score is not None and 0.0 <= u.anomaly_score <= 1.0
    assert u.model_version == "ueba-iforest-v1"
    assert coerce_ts(u.feature_window_start) == coerce_ts(enr.incident.first_seen)
    assert coerce_ts(u.feature_window_end) == coerce_ts(enr.incident.last_seen)
    assert u.observations and all(o.event_overlap for o in u.observations)


def test_available_not_anomalous():
    evts = background(users=("alice",), per=12)
    by_id = {e["event_id"]: e for e in evts}
    model = fit_model([])
    # Established window (prior history, known IP): typical behavior.
    dets = [devt("AUTH-002", user="alice", severity="MEDIUM", start_min=390,
                 evidence=[evts[6]["event_id"]])]
    enr, mp = incident_for_dets(dets, by_id)
    (wrapped,) = attach_ueba([enr], by_id, model)
    assert wrapped.ueba.available
    assert wrapped.ueba.anomaly_flag is False


def test_unavailable_model():
    evts = background(users=("alice",), per=6)
    by_id = {e["event_id"]: e for e in evts}
    dets = [devt("AUTH-002", user="alice", severity="MEDIUM", start_min=0,
                 evidence=[evts[0]["event_id"]])]
    enr, mp = incident_for_dets(dets, by_id)
    (wrapped,) = attach_ueba([enr], by_id, None)
    assert wrapped.ueba.available is False
    assert wrapped.ueba.anomaly_score is None
    assert wrapped.ueba.anomaly_flag is None


def test_empty_context_no_crash():
    dets = [devt("AUTH-002", user="alice", severity="MEDIUM", start_min=0)]
    enr, mp = incident_for_dets(dets, {})
    (wrapped,) = attach_ueba([enr], {}, fit_model([]))
    assert wrapped.ueba.available is False


def test_deterministic_evidence():
    evts = loud_user_events()
    by_id = {e["event_id"]: e for e in background() + evts}
    model = fit_model(evts)
    dets = [devt("AUTH-001", user="mallory", start_min=0,
                 evidence=[evts[0]["event_id"], evts[1]["event_id"]])]
    enr, mp = incident_for_dets(dets, by_id)
    a = attach_ueba([enr], by_id, model)[0].ueba.model_dump()
    b = attach_ueba([enr], by_id, model)[0].ueba.model_dump()
    assert a == b


def test_shuffle_invariant():
    import random

    evts = loud_user_events()
    bg = background()
    model = fit_model(evts)
    dets = [devt("AUTH-001", user="mallory", start_min=0,
                 evidence=[evts[0]["event_id"], evts[1]["event_id"]]),
            devt("DATA-001", user="mallory", start_min=40,
                 evidence=[evts[3]["event_id"]],
                 extra_meta={"bytes_sent": 3_000_000_000, "threshold": 1_000_000_000})]
    both = bg + evts
    by_id = {e["event_id"]: e for e in both}
    enr, mp = incident_for_dets(dets, by_id)
    a = attach_ueba([enr], by_id, model)[0].ueba.model_dump()
    sh = list(both)
    random.Random(3).shuffle(sh)
    by_id2 = {e["event_id"]: e for e in sh}
    b = attach_ueba([enr], by_id2, model)[0].ueba.model_dump()
    assert a == b


def test_no_future_leakage():
    evts = loud_user_events()
    by_id = {e["event_id"]: e for e in background() + evts}
    model = fit_model(evts)
    dets = [devt("AUTH-001", user="mallory", start_min=0,
                 evidence=[evts[0]["event_id"], evts[1]["event_id"]])]
    enr, mp = incident_for_dets(dets, by_id)
    before = attach_ueba([enr], by_id, model)[0].ueba.model_dump()
    future = [h(user="mallory", minutes=60 * 30, bytes_sent=9_000_000_000,
                event_type="data_transfer", source="firewall", status="completed")]
    by_id2 = dict(by_id)
    by_id2.update({e["event_id"]: e for e in future})
    after = attach_ueba([enr], by_id2, model)[0].ueba.model_dump()
    assert before == after


def test_risk_isolation():
    evts = loud_user_events()
    by_id = {e["event_id"]: e for e in background() + evts}
    model = fit_model(evts)
    dets = [devt("AUTH-001", user="mallory", start_min=0,
                 evidence=[evts[0]["event_id"], evts[1]["event_id"]]),
            devt("DATA-001", user="mallory", start_min=40,
                 evidence=[evts[3]["event_id"]],
                 extra_meta={"bytes_sent": 3_000_000_000, "threshold": 1_000_000_000})]
    enr, mp = incident_for_dets(dets, by_id)
    s0, b0, _ = score_risk(enr.incident, mp, map_incident(enr.incident, mp))
    (wrapped,) = attach_ueba([enr], by_id, model)
    assert wrapped.enriched.risk_score == s0 == enr.risk_score
    assert wrapped.enriched.risk_band == enr.risk_band
    assert wrapped.enriched.risk_breakdown == b0 == enr.risk_breakdown
    assert wrapped.enriched.incident == enr.incident


def test_no_ground_truth_in_slice7_code():
    import ast

    targets = {"scenario_id", "scenario_type", "synthetic", "raw_event", "seed"}
    hits = []
    for name in ("evidence.py", "attach.py"):
        path = BACKEND / "app" / "services" / "ueba" / name
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in targets:
                hits.append(f"{name}:{node.attr} (attribute)")
            elif isinstance(node, ast.Constant) and node.value in targets:
                hits.append(f"{name}:{node.value!r} (literal)")
    assert hits == [], f"ground-truth leakage: {hits}"


def test_version_from_model_not_hardcoded():
    cfg = UebaConfig(model_version="custom-v9", feature_version="custom-f9")
    evts = background(users=("alice",), per=12)
    obs = build_observations(evts, cfg)
    model = UebaModel(cfg).fit(obs)
    target = evts[4]
    mins = int((coerce_ts(target["timestamp"]) - T0).total_seconds() // 60)
    dets = [devt("AUTH-002", user="alice", severity="MEDIUM", start_min=mins,
                 evidence=[target["event_id"]])]
    by_id = {e["event_id"]: e for e in evts}
    enr, mp = incident_for_dets(dets, by_id)
    (wrapped,) = attach_ueba([enr], by_id, model)
    if wrapped.ueba.available:
        assert wrapped.ueba.model_version == "custom-v9"
