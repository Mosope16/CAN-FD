"""Embedded-Friendly Decision Tree Classifier for CAN-FD Intrusion Detection.

Implements explainable, lightweight decision tree inference using scikit-learn
with constrained tree depths (5-8) and balanced class weighting.
"""

from __future__ import annotations

import pickle
from typing import Optional, Tuple
import numpy as np
from sklearn.tree import DecisionTreeClassifier

from src.features.frame_features import FEATURE_NAMES


CLASS_NAMES: dict[int, str] = {
    0: "Normal",
    1: "DoS",
    2: "Fuzzing",
    3: "Spoofing",
    4: "Replay",
    5: "Suppression",
}


class CANFDDecisionTree:
    """Decision Tree intrusion detection model."""

    def __init__(
        self,
        max_depth: int = 7,
        min_samples_split: int = 5,
        min_samples_leaf: int = 2,
        random_state: int = 42,
    ) -> None:
        self.max_depth = max_depth
        self.min_samples_split = min_samples_split
        self.min_samples_leaf = min_samples_leaf
        self.random_state = random_state

        self.model = DecisionTreeClassifier(
            max_depth=self.max_depth,
            min_samples_split=self.min_samples_split,
            min_samples_leaf=self.min_samples_leaf,
            class_weight="balanced",
            random_state=self.random_state,
        )
        self.is_fitted = False

    def fit(self, X: np.ndarray, y: np.ndarray) -> CANFDDecisionTree:
        """Train the decision tree on integer feature matrix X and label vector y."""
        self.model.fit(X, y)
        self.is_fitted = True
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Classify input feature vectors."""
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before predict() is called.")
        return self.model.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Return class probability distributions."""
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before predict_proba() is called.")
        return self.model.predict_proba(X)

    def save(self, filepath: str) -> None:
        """Serialize model to pickle file."""
        with open(filepath, "wb") as f:
            pickle.dump(self, f)

    @classmethod
    def load(cls, filepath: str) -> CANFDDecisionTree:
        """Deserialize model from pickle file."""
        with open(filepath, "rb") as f:
            return pickle.load(f)
