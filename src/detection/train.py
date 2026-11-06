"""Model Training and Hyperparameter Tuning Engine.

Trains Decision Tree models across depths 5-8, evaluates validation metrics,
saves serialized artifacts, and exports C source code.
"""

from __future__ import annotations

import os
from typing import Dict, Tuple
import numpy as np

from src.detection.decision_tree import CANFDDecisionTree
from src.detection.export_c import CCodeExporter
from src.evaluation.metrics import compute_classification_metrics


def train_and_select_best_model(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    candidate_depths: list[int] = [5, 6, 7, 8],
    model_save_path: str = "models/decision_tree.pkl",
    export_c_dir: str = "models/exported",
) -> tuple[CANFDDecisionTree, dict[int, dict]]:
    """Train decision trees across depths and select optimal model based on validation macro F1.

    Returns:
        (best_model, evaluation_summary_by_depth)
    """
    best_model: CANFDDecisionTree | None = None
    best_f1 = -1.0
    best_depth = 6
    depth_reports = {}

    for depth in candidate_depths:
        dt = CANFDDecisionTree(max_depth=depth, random_state=42)
        dt.fit(X_train, y_train)

        val_preds = dt.predict(X_val)
        val_metrics = compute_classification_metrics(y_val, val_preds)
        macro_f1 = val_metrics["macro_f1"]

        depth_reports[depth] = val_metrics

        if macro_f1 > best_f1:
            best_f1 = macro_f1
            best_model = dt
            best_depth = depth

    assert best_model is not None

    # Save best serialized model
    os.makedirs(os.path.dirname(model_save_path), exist_ok=True)
    best_model.save(model_save_path)

    # Export C implementation and verify 100% agreement on validation set
    exporter = CCodeExporter(best_model)
    agreement = exporter.compile_and_verify(
        X_test=X_val,
        y_expected=best_model.predict(X_val),
        output_dir=export_c_dir,
    )
    assert agreement == 1.0, f"C export verification failed! Agreement: {agreement}"

    return best_model, depth_reports
