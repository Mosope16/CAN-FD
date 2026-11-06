"""Performance and Classification Metrics Calculator.

Computes accuracy, precision, recall, F1-score, False Positive Rate (FPR),
and confusion matrices aligned with ISO/SAE 21434 verification evidence.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple
import numpy as np
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score

from src.detection.decision_tree import CLASS_NAMES


def compute_classification_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
) -> dict[str, Any]:
    """Calculate comprehensive evaluation metrics per attack class and macro-average.

    Returns:
        Dictionary containing overall accuracy, macro precision/recall/F1,
        per-class metrics, false positive rate (FPR), and confusion matrix.
    """
    classes = sorted(list(CLASS_NAMES.keys()))
    cm = confusion_matrix(y_true, y_pred, labels=classes)

    total_samples = len(y_true)
    accuracy = float(np.mean(y_true == y_pred)) if total_samples > 0 else 0.0

    # Macro averages
    macro_precision = float(precision_score(y_true, y_pred, average="macro", zero_division=0))
    macro_recall = float(recall_score(y_true, y_pred, average="macro", zero_division=0))
    macro_f1 = float(f1_score(y_true, y_pred, average="macro", zero_division=0))

    # Calculate False Positive Rate (FPR) on benign Class 0 (Normal)
    # Class 0: True Normal = y_true == 0. FP = (y_true == 0) & (y_pred != 0)
    normal_mask = (y_true == 0)
    total_normal = int(np.sum(normal_mask))
    if total_normal > 0:
        false_positives = int(np.sum((y_true == 0) & (y_pred != 0)))
        fpr = float(false_positives / total_normal)
    else:
        fpr = 0.0

    # Per-class metrics
    per_class = {}
    for cls_idx in classes:
        cls_name = CLASS_NAMES[cls_idx]
        mask_true = (y_true == cls_idx)
        mask_pred = (y_pred == cls_idx)
        tp = int(np.sum(mask_true & mask_pred))
        fp = int(np.sum((~mask_true) & mask_pred))
        fn = int(np.sum(mask_true & (~mask_pred)))
        tn = int(np.sum((~mask_true) & (~mask_pred)))

        prec = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
        rec = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
        f1 = float(2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0

        per_class[cls_name] = {
            "class_id": cls_idx,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
            "support": int(np.sum(mask_true)),
        }

    return {
        "accuracy": round(accuracy, 4),
        "macro_precision": round(macro_precision, 4),
        "macro_recall": round(macro_recall, 4),
        "macro_f1": round(macro_f1, 4),
        "false_positive_rate": round(fpr, 4),
        "per_class": per_class,
        "confusion_matrix": cm.tolist(),
        "total_samples": total_samples,
    }
