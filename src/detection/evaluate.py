"""Comprehensive IDS Evaluation and Ablation Suite.

Implements multi-class testing, feature ablation analysis, and unseen-attack
generalisation experiments conforming to ISO/SAE 21434 evidence targets.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional, Tuple
import numpy as np

from src.detection.anomaly_detector import NormalTrafficAnomalyDetector
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
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: Optional[np.ndarray] = None,
    y_test: Optional[np.ndarray] = None,
    excluded_attacks: list[int] = [1, 2, 3, 4],  # DoS, Fuzzing, Spoofing, Replay
) -> dict[str, dict[str, Any]]:
    """Evaluate detection when one attack category is omitted from the training dataset.

    Compares:
    1. Standalone Supervised Decision Tree (trained with the attack category excluded)
    2. Complementary Normal-Only Anomaly Detector (trained strictly on Class 0 Normal data)
    3. Dual-Engine IDS Architecture (Supervised Tree + Normal Anomaly Detector)
    """
    # Backwards-compatible handling if called with (X, y)
    if X_test is None or y_test is None:
        X_test = X_train
        y_test = y_train

    # Fit Normal Anomaly Detector strictly on benign Class 0 training data
    normal_mask_tr = (y_train == 0)
    anomaly_detector = NormalTrafficAnomalyDetector(contamination=0.001, random_state=42)
    anomaly_detector.fit(X_train[normal_mask_tr])

    results: dict[str, dict[str, Any]] = {}

    for exc_cls in excluded_attacks:
        exc_name = CLASS_NAMES[exc_cls]

        # 1. Train Decision Tree excluding exc_cls
        train_mask = (y_train != exc_cls)
        dt_model = CANFDDecisionTree(max_depth=6, random_state=42)
        dt_model.fit(X_train[train_mask], y_train[train_mask])

        # 2. Test strictly on unseen attack samples
        test_mask = (y_test == exc_cls)
        X_test_unseen = X_test[test_mask]

        if len(X_test_unseen) > 0:
            # Supervised DT prediction (non-zero = flagged as anomalous)
            dt_preds = dt_model.predict(X_test_unseen)
            dt_anom = (dt_preds != 0)
            dt_recall = float(np.mean(dt_anom))

            # Complementary Anomaly Detector prediction
            ad_preds = anomaly_detector.predict_anomaly(X_test_unseen)
            ad_anom = (ad_preds == 1)
            ad_recall = float(np.mean(ad_anom))

            # Dual-Engine prediction: alert if either engine detects anomaly
            dual_anom = dt_anom | ad_anom
            dual_recall = float(np.mean(dual_anom))

            results[f"Excluded_{exc_name}"] = {
                "excluded_class_id": exc_cls,
                "unseen_samples": len(X_test_unseen),
                "dt_alone_recall": round(dt_recall, 4),
                "ad_alone_recall": round(ad_recall, 4),
                "dual_engine_recall": round(dual_recall, 4),
                "flagged_as_anomalous": int(np.sum(dual_anom)),
                "anomaly_recall": round(dual_recall, 4),
            }

    return results
