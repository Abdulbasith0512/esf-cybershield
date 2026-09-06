"""Model persistence: joblib artifact + JSON training manifest."""

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import joblib

from app.services.ueba.config import UebaConfig
from app.services.ueba.model import UebaModel

ARTIFACT_DIR = Path("models/ueba")
MODEL_FILE = "model.joblib"
MANIFEST_FILE = "manifest.json"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _portable_path(path: str | Path) -> str:
    # Never store machine-specific absolute paths in the manifest.
    try:
        return os.path.relpath(path, Path.cwd())
    except Exception:
        return str(path)


def _versions() -> dict:
    out = {}
    for name in ("sklearn", "numpy", "joblib"):
        try:
            out[name] = __import__(name).__version__
        except Exception:
            out[name] = "unknown"
    return out


def save(model: UebaModel, dataset_path: str, train_rows: int,
         eval_spec: str, out_dir: str | Path = ARTIFACT_DIR) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    joblib.dump(model.state_dict(), out / MODEL_FILE)
    manifest = {
        "model_version": model.config.model_version,
        "feature_version": model.config.feature_version,
        "algorithm": "sklearn.ensemble.IsolationForest",
        "random_state": model.config.random_state,
        "n_estimators": model.config.n_estimators,
        "contamination": model.config.contamination,
        "window_hours": model.config.window_hours,
        "training_dataset": _portable_path(dataset_path),
        "training_dataset_sha256": _sha256(Path(dataset_path)),
        "training_row_count": train_rows,
        "eval_spec": eval_spec,
        "feature_columns": list(model.config.feature_columns),
        "threshold": model.threshold,
        "train_score_min": model.train_min,
        "train_score_max": model.train_max,
        "package_versions": _versions(),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    (out / MANIFEST_FILE).write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return out / MANIFEST_FILE


def load(model_path: str | Path, manifest_path: str | Path | None = None) -> UebaModel:
    state = joblib.load(model_path)
    model = UebaModel(config=state["config"])
    model.scaler, model.forest = state["scaler"], state["forest"]
    model.train_min, model.train_max = state["train_min"], state["train_max"]
    model.threshold = state["threshold"]
    return model
