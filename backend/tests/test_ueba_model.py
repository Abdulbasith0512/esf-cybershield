"""UEBA model tests: reproducibility, bounds, persistence, separation."""

import shutil
import sys
import tempfile
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.services.ueba.config import UebaConfig  # noqa: E402
from app.services.ueba.features import build_observations  # noqa: E402
from app.services.ueba.model import UebaModel  # noqa: E402
from app.services.ueba.scoring import score_observations  # noqa: E402
from app.services.ueba.serialization import load, save  # noqa: E402
from test_ueba_features import CFG, evt  # noqa: E402


def varied(n=60, user="alice"):
    out = []
    for i in range(n):
        kw = {}
        if i % 7 == 0:
            kw = {"status": "failed"}
        if i % 11 == 0:
            kw = {"event_type": "dns_query", "domain": "intranet.local",
                  "destination_ip": "10.10.0.53", "status": "resolved"}
        out.append(evt(user=user, minutes=i * 13, ip=f"10.0.0.{1 + (i % 3)}", **kw))
    return out


def test_reproducible_training():
    obs = build_observations(varied(), CFG)
    a = UebaModel(CFG).fit(obs)
    b = UebaModel(CFG).fit(obs)
    sa = sorted(score_observations(obs, a, CFG), key=lambda r: (r.observation_time, r.entity_key))
    sb = sorted(score_observations(obs, b, CFG), key=lambda r: (r.observation_time, r.entity_key))
    assert [(r.anomaly_score, r.anomaly_flag) for r in sa] == \
           [(r.anomaly_score, r.anomaly_flag) for r in sb]


def test_scores_bounded_and_flag_deterministic():
    obs = build_observations(varied(), CFG)
    model = UebaModel(CFG).fit(obs)
    res = score_observations(obs, model, CFG)
    assert all(0.0 <= r.anomaly_score <= 1.0 for r in res)
    again = score_observations(obs, model, CFG)
    assert [(r.anomaly_score, r.anomaly_flag) for r in again] == \
           [(r.anomaly_score, r.anomaly_flag) for r in res]


def test_versions_present():
    obs = build_observations(varied(), CFG)
    res = score_observations(obs, UebaModel(CFG).fit(obs), CFG)
    assert all(r.model_version == "ueba-iforest-v1" for r in res)
    assert all(r.feature_version == "ueba-features-v1" for r in res)


def test_serialization_roundtrip(tmpdir=None):
    import tempfile as _tf

    d = Path(_tf.mkdtemp(prefix="esf-ueba-"))
    try:
        obs = build_observations(varied(), CFG)
        model = UebaModel(CFG).fit(obs)
        before = [(r.anomaly_score, r.anomaly_flag) for r in score_observations(obs, model, CFG)]
        import json

        (d / "data.jsonl").write_text("\n".join(json.dumps({"x": 1})), encoding="utf-8")
        save(model, str(d / "data.jsonl"), len(obs), "unit-test", d)
        assert (d / "manifest.json").exists() and (d / "model.joblib").exists()
        back = load(d / "model.joblib")
        after = [(r.anomaly_score, r.anomaly_flag) for r in score_observations(obs, back, CFG)]
        assert before == after
        manifest = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
        for key in ("model_version", "feature_version", "algorithm", "random_state",
                    "n_estimators", "contamination", "training_dataset_sha256",
                    "training_row_count", "feature_columns", "created_at"):
            assert key in manifest, f"manifest missing {key}"
        assert manifest["training_row_count"] == len(obs)
        assert "secret" not in json.dumps(manifest).lower()
        assert manifest["feature_columns"] == list(CFG.feature_columns)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_eval_columns_match_and_no_refit():
    train = build_observations(varied(), CFG)
    model = UebaModel(CFG).fit(train)
    scaler_id = id(model.scaler)
    eval_obs = build_observations(varied(user="bob"), CFG)
    res = score_observations(eval_obs, model, CFG)
    assert id(model.scaler) == scaler_id  # transform-only, never refit
    assert all(set(r.metadata["feature_context"]) <= set(CFG.feature_columns) for r in res)


def test_labels_cannot_affect_features_or_scores():
    base = varied()
    relabeled = []
    for e in base:
        c = dict(e, raw_event={"scenario_type": "tampered", "scenario_id": "x",
                               "synthetic": False, "seed": 999})
        relabeled.append(c)
    assert build_observations(base, CFG) == build_observations(relabeled, CFG)


def test_different_config_can_differ():
    obs = build_observations(varied(), CFG)
    a = [r.anomaly_score for r in score_observations(obs, UebaModel(CFG).fit(obs), CFG)]
    cfg2 = UebaConfig(contamination=0.30, random_state=7)
    b = [r.anomaly_score for r in score_observations(obs, UebaModel(cfg2).fit(obs), cfg2)]
    assert a != b
