"""Comprehensive IDS Evaluation and Ablation Suite.

Implements multi-class testing, feature ablation analysis, and unseen-attack
generalisation experiments conforming to ISO/SAE 21434 evidence targets.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Tuple
import numpy as np

from src.detection.decision_tree import CANFDDecisionTree, CLASS_NAMES
from src.evaluation.metrics import compute_classification_metrics
from src.features.frame_features import FEATURE_NAMES


def run_feature_ablation_study(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
) -> dict[str, dict[str, Any]]:
    """Compare performance across feature subset configurations.

    A: Per-frame only (indices: 0, 1, 2, 3, 4, 7, 8, 9)
    B: Per-frame + Sliding-window rates (adds indices: 5, 6, 12, 13)
    C: Complete feature set (adds indices: 10, 11 - protocol & missing)
    """
    # Feature indices
    per_frame_indices = [0, 1, 2, 3, 4, 7, 8, 9]
    window_indices = per_frame_indices + [5, 6, 12, 13]
    full_indices = list(range(len(FEATURE_NAMES)))

    configs = {
        "Config_A_PerFrameOnly": per_frame_indices,
        "Config_B_PerFrame_Plus_Window": window_indices,
        "Config_C_Complete_FullFeatures": full_indices,
    }

    ablation_results = {}
    for name, indices in configs.items():
        X_tr = X_train[:, indices]
        X_te = X_test[:, indices]

        model = CANFDDecisionTree(max_depth=6, random_state=42)
        model.fit(X_tr, y_train)
        preds = model.predict(X_te)
        metrics = compute_classification_metrics(y_test, preds)

        ablation_results[name] = {
            "num_features": len(indices),
            "features_used": [FEATURE_NAMES[i] for i in indices],
            "accuracy": metrics["accuracy"],
            "macro_f1": metrics["macro_f1"],
            "macro_recall": metrics["macro_recall"],
            "false_positive_rate": metrics["false_positive_rate"],
        }

    return ablation_results


def run_unseen_attack_evaluation(
    X: np.ndarray,
    y: np.ndarray,
    excluded_attacks: list[int] = [1, 2, 3, 4],  # DoS, Fuzzing, Spoofing, Replay
) -> dict[str, dict[str, Any]]:
    """Evaluate detection when one attack category is omitted from the training dataset.

    Measures whether the model flags the excluded attack as an anomaly (binary normal vs anomaly).
    """
    results = {}

    for exc_cls in excluded_attacks:
        exc_name = CLASS_NAMES[exc_cls]

        # Training set excludes exc_cls
        train_mask = (y != exc_cls)
        X_train = X[train_mask]
        y_train = y[train_mask]

        # Fit model on known classes
        model = CANFDDecisionTree(max_depth=6, random_state=42)
        model.fit(X_train, y_train)

        # Test set is the excluded attack samples
        test_mask = (y == exc_cls)
        X_test_unseen = X[test_mask]

        if len(X_test_unseen) > 0:
            preds = model.predict(X_test_unseen)
            # Anomaly detection: did it flag as non-zero (non-normal)?
            flagged_as_anomaly = np.sum(preds != 0)
            anomaly_recall = float(flagged_as_anomaly / len(X_test_unseen))

            results[f"Excluded_{exc_name}"] = {
                "excluded_class_id": exc_cls,
                "unseen_samples": len(X_test_unseen),
                "flagged_as_anomalous": int(flagged_as_anomaly),
                "anomaly_recall": round(anomaly_recall, 4),
            }

    return results
