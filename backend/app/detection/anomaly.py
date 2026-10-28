"""
CyberSleuth AI – Anomaly Detection (IsolationForest)
Member 2: Backend & Data Engineering

Wraps scikit-learn IsolationForest for per-event anomaly scoring.
Model is trained on the benign baseline dataset at startup if not found.
"""
import os
import json
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
from typing import List, Dict, Any

MODELS_DIR = Path(__file__).parent.parent.parent / "models"
MODEL_PATH = MODELS_DIR / "isolation_forest.pkl"
ENCODER_PATH = MODELS_DIR / "label_encoders.pkl"


# ── Feature extraction ────────────────────────────────────────────────────────

def extract_features(events: List[Dict[str, Any]]) -> pd.DataFrame:
    """Convert raw event dicts to a numeric feature matrix."""
    df = pd.DataFrame(events)

    # Hour of day (time-based anomaly)
    if "timestamp" in df.columns:
        df["hour_of_day"] = pd.to_datetime(df["timestamp"]).dt.hour
    else:
        df["hour_of_day"] = 12

    # Numeric features
    num_cols = ["hour_of_day", "dest_port"]
    for col in num_cols:
        if col not in df.columns:
            df[col] = 0
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    # Categorical encode
    cat_cols = ["event_type", "username", "host"]
    encoders: Dict[str, LabelEncoder] = {}
    if ENCODER_PATH.exists():
        encoders = joblib.load(ENCODER_PATH)

    for col in cat_cols:
        if col not in df.columns:
            df[col] = "unknown"
        le = encoders.get(col, LabelEncoder())
        df[col + "_enc"] = le.fit_transform(df[col].fillna("unknown").astype(str))

    feature_cols = ["hour_of_day", "dest_port"] + [c + "_enc" for c in cat_cols]
    return df[feature_cols].fillna(0)


# ── Train ─────────────────────────────────────────────────────────────────────

def train_from_benign_dataset(dataset_path: str | None = None):
    """Train IsolationForest on the benign baseline dataset."""
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    if dataset_path is None:
        # Try default path relative to repo root
        base = Path(__file__).parent.parent.parent.parent
        candidates = [
            base / "CyberSleuth_Synthetic_Dataset" / "datasets" / "large_scale_benign_baseline.json",
            base / "CyberSleuth_Synthetic_Dataset" / "benign_events.json",
        ]
        dataset_path = next((str(p) for p in candidates if p.exists()), None)

    if not dataset_path or not Path(dataset_path).exists():
        print("[AnomalyDetection] Benign dataset not found – using random baseline.")
        X = np.random.randn(500, 5)
        model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
        model.fit(X)
        joblib.dump(model, MODEL_PATH)
        return

    with open(dataset_path) as f:
        events = json.load(f)

    X = extract_features(events)
    model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    model.fit(X)
    joblib.dump(model, MODEL_PATH)
    print(f"[AnomalyDetection] Model trained on {len(events)} benign events → {MODEL_PATH}")


# ── Score ─────────────────────────────────────────────────────────────────────

def score_events(events: List[Dict[str, Any]]) -> List[float]:
    """Return anomaly scores (0 = normal, 1 = highly anomalous) for each event."""
    if not MODEL_PATH.exists():
        train_from_benign_dataset()

    model: IsolationForest = joblib.load(MODEL_PATH)
    X = extract_features(events)
    # IsolationForest returns -1 (anomaly) / 1 (normal); scores are negative for anomalies
    raw_scores = model.decision_function(X)
    # Normalize to [0, 1]: lower decision_function → higher anomaly score
    normalized = 1.0 - (raw_scores - raw_scores.min()) / (raw_scores.max() - raw_scores.min() + 1e-9)
    return normalized.tolist()
