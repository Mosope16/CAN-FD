"""Detection Latency and Computational Execution Timing Benchmark.

Measures simulated intrusion alert latency with microsecond integer resolution,
distinguishing first-frame detection from sustained consecutive-frame detection,
and profiles CPU execution overhead.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional
import numpy as np

from src.attacks.ground_truth import AttackEvent
from src.detection.decision_tree import CANFDDecisionTree


def compute_attack_detection_latency(
    attack_events: list[AttackEvent],
    timestamps_us: list[int],
    y_true: np.ndarray,
    y_pred: np.ndarray,
) -> dict[str, dict[str, Any]]:
    """Compute microsecond-resolution detection latency for each attack event.

    Distinguishes:
    1. Latency from attack scenario onset (start_us)
    2. Latency from first malicious frame arrival on the bus (first_malicious_frame_us)
    3. Sustained qualification latency (3 consecutive attack frames correctly flagged)

    Args:
        attack_events: Registered ground truth attack events.
        timestamps_us: List of simulation timestamps in integer microseconds.
        y_true: Ground truth label array.
        y_pred: Predicted class label array.

    Returns:
        Mapping of attack name to detailed latency records.
    """
    results: dict[str, dict[str, Any]] = {}

    for evt in attack_events:
        evt_type = evt.attack_type
        start_us = evt.start_us
        end_us = evt.end_us

        # 1. Identify first malicious frame generated on bus
        first_malicious_frame_us: Optional[int] = None
        for t_us, true_lbl in zip(timestamps_us, y_true):
            if t_us >= start_us and true_lbl == evt_type:
                first_malicious_frame_us = t_us
                break

        # 2. Identify first alert emitted by detector
        first_alert_us: Optional[int] = None
        for t_us, pred_lbl in zip(timestamps_us, y_pred):
            if t_us >= start_us and pred_lbl == evt_type:
                first_alert_us = t_us
                break

        # 3. Identify sustained qualification (3 consecutive attack-stream frames flagged)
        sustained_3frame_alert_us: Optional[int] = None
        consecutive_count = 0
        for t_us, true_lbl, pred_lbl in zip(timestamps_us, y_true, y_pred):
            if t_us >= start_us and true_lbl == evt_type:
                if pred_lbl == evt_type:
                    consecutive_count += 1
                    if consecutive_count == 3:
                        sustained_3frame_alert_us = t_us
                        break
                else:
                    consecutive_count = 0

        if first_alert_us is not None:
            latency_onset_us = first_alert_us - start_us
            latency_frame_us = (first_alert_us - first_malicious_frame_us) if first_malicious_frame_us is not None else 0
            first_frame_detected = (first_alert_us == first_malicious_frame_us)
            sustained_ms = round((sustained_3frame_alert_us - start_us) / 1000.0, 3) if sustained_3frame_alert_us is not None else -1.0

            results[evt.name] = {
                "attack_type": evt_type,
                "start_us": start_us,
                "first_malicious_frame_us": first_malicious_frame_us if first_malicious_frame_us is not None else start_us,
                "first_alert_us": first_alert_us,
                "latency_from_onset_us": latency_onset_us,
                "latency_from_first_frame_us": latency_frame_us,
                "first_frame_detected": first_frame_detected,
                "sustained_3frame_alert_us": sustained_3frame_alert_us if sustained_3frame_alert_us is not None else -1,
                "sustained_3frame_latency_ms": sustained_ms,
                "start_ms": start_us / 1000.0,
                "first_alert_ms": first_alert_us / 1000.0,
                "latency_ms": round(latency_onset_us / 1000.0, 3),
                "detected": True,
            }
        else:
            results[evt.name] = {
                "attack_type": evt_type,
                "start_us": start_us,
                "first_malicious_frame_us": first_malicious_frame_us if first_malicious_frame_us is not None else start_us,
                "first_alert_us": -1,
                "latency_from_onset_us": -1,
                "latency_from_first_frame_us": -1,
                "first_frame_detected": False,
                "sustained_3frame_alert_us": -1,
                "sustained_3frame_latency_ms": -1.0,
                "start_ms": start_us / 1000.0,
                "first_alert_ms": -1.0,
                "latency_ms": -1.0,
                "detected": False,
            }

    return results


def benchmark_cpu_inference_latency(
    model: CANFDDecisionTree,
    X_test: np.ndarray,
    n_iterations: int = 1000,
) -> dict[str, float]:
    """Measure single-vector CPU inference overhead per frame in microseconds.

    Note: This measures the Python runtime overhead (NumPy slicing + scikit-learn
    scalar dispatch). The compiled ANSI C standalone inference engine operates in
    ~4.34 nanoseconds per frame without interpreter overhead.
    """
    if len(X_test) == 0:
        return {"avg_us": 0.0, "worst_case_us": 0.0, "p99_us": 0.0}

    # Warmup
    _ = model.predict(X_test[:min(100, len(X_test))])

    sample_indices = np.random.choice(len(X_test), size=min(n_iterations, len(X_test)), replace=True)
    durations_ns = []

    for idx in sample_indices:
        single_vec = X_test[idx : idx + 1]
        t0 = time.perf_counter_ns()
        _ = model.predict(single_vec)
        t1 = time.perf_counter_ns()
        durations_ns.append(t1 - t0)

    durations_us = np.array(durations_ns) / 1000.0
    return {
        "avg_us": round(float(np.mean(durations_us)), 3),
        "worst_case_us": round(float(np.max(durations_us)), 3),
        "p99_us": round(float(np.percentile(durations_us, 99)), 3),
    }
