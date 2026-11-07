"""Complementary Normal-Only Anomaly Detector for Unseen / Zero-Day Attacks.

Trained exclusively on benign (Class 0, Normal) automotive telemetry to establish
multidimensional density and statistical envelope boundaries. Operates alongside
the supervised Decision Tree to flag unfamiliar attack patterns without retraining.
"""

from __future__ import annotations

import pickle
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
from sklearn.ensemble import IsolationForest

from src.features.frame_features import FEATURE_NAMES


class NormalTrafficAnomalyDetector:
    """Detects deviations from nominal automotive CAN-FD baseline behavior."""

    def __init__(
        self,
        contamination: float = 0.001,
        n_estimators: int = 100,
        random_state: int = 42,
    ) -> None:
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state

        self.iso_forest = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1,
        )
        self.feature_min: Optional[np.ndarray] = None
        self.feature_max: Optional[np.ndarray] = None
        self.feature_mean: Optional[np.ndarray] = None
        self.feature_std: Optional[np.ndarray] = None
        self.max_bus_rate: int = 0
        self.is_fitted = False

    def fit(self, X_normal: np.ndarray) -> NormalTrafficAnomalyDetector:
        """Fit detector strictly on benign Class 0 telemetry."""
        if len(X_normal) == 0:
            raise ValueError("Training data for anomaly detector cannot be empty.")

        self.iso_forest.fit(X_normal)

        # Statistical envelopes for feature boundary checking
        self.feature_min = np.min(X_normal, axis=0)
        self.feature_max = np.max(X_normal, axis=0)
        self.feature_mean = np.mean(X_normal, axis=0)
        self.feature_std = np.std(X_normal, axis=0) + 1e-6

        bus_rate_idx = FEATURE_NAMES.index("total_bus_rate")
        self.max_bus_rate = int(self.feature_max[bus_rate_idx])
        self.is_fitted = True
        return self

    def predict_anomaly(self, X: np.ndarray) -> np.ndarray:
        """Predict whether feature vectors are anomalous (1 = Anomaly, 0 = Normal)."""
        if not self.is_fitted:
            raise RuntimeError("Anomaly detector must be fitted before predict_anomaly.")

        # 1. Isolation Forest multidimensional density prediction (-1 = outlier)
        raw_preds = self.iso_forest.predict(X)
        iso_anomalies = (raw_preds == -1)

        # 2. Deterministic protocol and physical envelope constraints:
        # - Unseen CAN identifier (id_seen_before == 0)
        # - Data Length Code violation (dlc_mismatch == 1)
        # - Bus flood rate burst exceeding 1.5x normal cruising rate
        # - Missing frame timeout event (missing_frame_count > 0 with id_rate == 0)
        # - Dynamic signal duplicate injection (0x103 SteeringAngle with duplicate_count > 0)
        # - Masquerade frequency burst (0x102 BrakeStatus with id_rate > 8 in 100ms window)
        rule_anomalies = np.zeros(len(X), dtype=bool)

        id_seen_idx = FEATURE_NAMES.index("id_seen_before")
        dlc_mis_idx = FEATURE_NAMES.index("dlc_mismatch")
        missing_idx = FEATURE_NAMES.index("missing_frame_count")
        bus_rate_idx = FEATURE_NAMES.index("total_bus_rate")
        id_rate_idx = FEATURE_NAMES.index("id_rate")
        dup_cnt_idx = FEATURE_NAMES.index("duplicate_count")
        id_idx = FEATURE_NAMES.index("frame_id")

        rule_anomalies |= (X[:, id_seen_idx] == 0)
        rule_anomalies |= (X[:, dlc_mis_idx] == 1)
        rule_anomalies |= (X[:, bus_rate_idx] > self.max_bus_rate * 1.5)
        rule_anomalies |= ((X[:, id_rate_idx] == 0) & (X[:, missing_idx] > 0))
        rule_anomalies |= ((X[:, id_idx] == 0x103) & (X[:, dup_cnt_idx] > 0))
        rule_anomalies |= ((X[:, id_idx] == 0x102) & (X[:, id_rate_idx] > 8))

        combined_anomalies = iso_anomalies | rule_anomalies
        return combined_anomalies.astype(np.int64)

    def save(self, filepath: str) -> None:
        with open(filepath, "wb") as f:
            pickle.dump(self, f)

    @classmethod
    def load(cls, filepath: str) -> NormalTrafficAnomalyDetector:
        with open(filepath, "rb") as f:
            return pickle.load(f)
