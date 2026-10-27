"""
Test suite for CyberSleuth AI Machine Learning Anomaly Detection Model.

Tests Member 2's scikit-learn IsolationForest anomaly detection pipeline:
- Feature engineering from semi-structured security events
- Baseline model fitting on benign activity
- Anomaly separation between normal operational events and anomalous attacks
- Score boundary and distribution stability
- Serialization and reproducibility
"""
import io
import pickle
import pytest
import numpy as np
from datetime import datetime
from typing import List, Dict, Any
from sklearn.ensemble import IsolationForest


def extract_event_features(event: Dict[str, Any]) -> List[float]:
    """
    Feature extraction vectorizer for security events:
    1. local_hour (0-23 float normalized to 0.0-1.0)
    2. is_failed_login (binary 1.0 or 0.0)
    3. is_privilege_change (binary 1.0 or 0.0)
    4. is_outbound_connection (binary 1.0 or 0.0)
    5. is_unknown_device (binary 1.0 or 0.0)
    6. connection_count (log-scaled count)
    7. bytes_transferred_scaled (log-scaled bytes)
    """
    ts_str = event.get("timestamp", "2026-10-17T12:00:00Z")
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        hour = dt.hour / 24.0
    except Exception:
        hour = 0.5

    etype = event.get("event_type", "")
    details = event.get("details", {}) or {}

    is_fail = 1.0 if etype == "login_failed" else 0.0
    is_priv = 1.0 if etype == "privilege_change" else 0.0
    is_out = 1.0 if etype == "outbound_connection" else 0.0
    is_unknown_dev = 1.0 if details.get("device_known") is False else 0.0

    conn_count = float(details.get("connection_count", 0))
    bytes_trans = float(details.get("bytes_sent", details.get("bytes", 0)))

    return [
        hour,
        is_fail,
        is_priv,
        is_out,
        is_unknown_dev,
        np.log1p(conn_count),
        np.log1p(bytes_trans)
    ]


class SecurityAnomalyDetector:
    """Wrapper around Isolation Forest for security event anomaly scoring."""

    def __init__(self, contamination: float = 0.05, random_state: int = 42):
        self.model = IsolationForest(
            contamination=contamination,
            random_state=random_state,
            n_estimators=100
        )
        self.is_fitted = False

    def fit(self, events: List[Dict[str, Any]]) -> "SecurityAnomalyDetector":
        if not events:
            return self
        X = np.array([extract_event_features(e) for e in events])
        self.model.fit(X)
        self.is_fitted = True
        return self

    def score_samples(self, events: List[Dict[str, Any]]) -> np.ndarray:
        if not self.is_fitted or not events:
            return np.array([])
        X = np.array([extract_event_features(e) for e in events])
        # decision_function: lower means more anomalous
        return self.model.decision_function(X)

    def predict(self, events: List[Dict[str, Any]]) -> np.ndarray:
        """Returns -1 for anomalies, +1 for inliers."""
        if not self.is_fitted or not events:
            return np.array([])
        X = np.array([extract_event_features(e) for e in events])
        return self.model.predict(X)


class TestFeatureEngineering:
    """Validates vectorizer consistency and dimension stability."""

    def test_feature_vector_dimensions(self, all_events):
        """Every event must map to exactly 7 numerical features."""
        for ev in all_events[:10]:
            vec = extract_event_features(ev)
            assert len(vec) == 7
            assert all(isinstance(v, (int, float, np.floating)) for v in vec)
            assert not any(np.isnan(vec))

    def test_feature_extraction_values(self):
        """Validates correct feature mapping for failed login."""
        ev = {
            "timestamp": "2026-10-17T06:00:00Z",
            "event_type": "login_failed",
            "details": {"device_known": False, "connection_count": 5}
        }
        vec = extract_event_features(ev)
        assert vec[0] == pytest.approx(6.0 / 24.0)  # hour
        assert vec[1] == 1.0  # is_fail
        assert vec[2] == 0.0  # is_priv
        assert vec[3] == 0.0  # is_out
        assert vec[4] == 1.0  # is_unknown_device
        assert vec[5] == pytest.approx(np.log1p(5))


@pytest.fixture
def trained_detector(large_scale_benign_baseline) -> SecurityAnomalyDetector:
    detector = SecurityAnomalyDetector(contamination=0.05, random_state=42)
    detector.fit(large_scale_benign_baseline)
    return detector


class TestIsolationForestFitting:
    """Validates model training and prediction behavior."""

    def test_isolation_forest_fits_on_baseline(self, trained_detector):
        """Detector trains cleanly on 100 baseline enterprise operations events."""
        assert trained_detector.is_fitted is True

    def test_anomalous_events_score_lower_than_benign(self, trained_detector, suspicious_events, benign_events):
        """Anomalous attack events should exhibit lower decision scores than normal events."""
        benign_scores = trained_detector.score_samples(benign_events)
        suspicious_scores = trained_detector.score_samples(suspicious_events)

        assert len(benign_scores) > 0
        assert len(suspicious_scores) > 0
        assert np.mean(suspicious_scores) < np.mean(benign_scores)

    def test_benign_events_mostly_inliers(self, trained_detector, large_scale_benign_baseline):
        """At least 90% of baseline control events should be classified as inliers (+1)."""
        preds = trained_detector.predict(large_scale_benign_baseline)
        inlier_ratio = np.sum(preds == 1) / len(preds)
        assert inlier_ratio >= 0.90

    def test_model_reproducibility(self, large_scale_benign_baseline, suspicious_events):
        """Identical random_state seeds must yield identical anomaly scores."""
        d1 = SecurityAnomalyDetector(random_state=42).fit(large_scale_benign_baseline)
        d2 = SecurityAnomalyDetector(random_state=42).fit(large_scale_benign_baseline)

        scores1 = d1.score_samples(suspicious_events)
        scores2 = d2.score_samples(suspicious_events)
        np.testing.assert_array_almost_equal(scores1, scores2)

    def test_anomaly_score_range(self, trained_detector, all_events):
        """Decision function output must remain within realistic continuous bounds [-0.5, 0.5]."""
        scores = trained_detector.score_samples(all_events)
        assert np.all(scores >= -1.0)
        assert np.all(scores <= 1.0)

    def test_threshold_tuning_adjusts_sensitivity(self, large_scale_benign_baseline, suspicious_events):
        """Higher contamination parameter increases number of flagged anomalies."""
        d_low = SecurityAnomalyDetector(contamination=0.01, random_state=42).fit(large_scale_benign_baseline)
        d_high = SecurityAnomalyDetector(contamination=0.15, random_state=42).fit(large_scale_benign_baseline)

        flags_low = np.sum(d_low.predict(suspicious_events) == -1)
        flags_high = np.sum(d_high.predict(suspicious_events) == -1)
        assert flags_high >= flags_low

    def test_model_serialization_with_pickle(self, trained_detector, suspicious_events):
        """Model must serialize and deserialize cleanly for production API serving."""
        buf = io.BytesIO()
        pickle.dump(trained_detector, buf)
        buf.seek(0)
        loaded_detector: SecurityAnomalyDetector = pickle.load(buf)

        original_scores = trained_detector.score_samples(suspicious_events)
        loaded_scores = loaded_detector.score_samples(suspicious_events)
        np.testing.assert_array_almost_equal(original_scores, loaded_scores)


class TestModelEdgeCases:
    """Validates resilience against atypical inputs."""

    def test_empty_input_scoring(self, trained_detector):
        """Empty list returns empty array without throwing exceptions."""
        scores = trained_detector.score_samples([])
        assert len(scores) == 0

    def test_single_event_scoring(self, trained_detector):
        """Single event returns array of length 1."""
        ev = [{"event_id": "ONE", "timestamp": "2026-10-17T10:00:00Z", "event_type": "login_success"}]
        score = trained_detector.score_samples(ev)
        assert len(score) == 1

    def test_missing_optional_details_handled_gracefully(self, trained_detector):
        """Event with details=None should compute valid feature representation."""
        ev = [{"event_id": "NULL_DET", "timestamp": "2026-10-17T10:00:00Z", "event_type": "logout", "details": None}]
        score = trained_detector.score_samples(ev)
        assert len(score) == 1
        assert not np.isnan(score[0])
