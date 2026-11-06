"""Detection Latency and Computational Execution Timing Benchmark.

Measures simulated intrusion alert latency (attack onset to first detection)
and real CPU execution overhead per frame (WCET and average latency).
"""

from __future__ import annotations

import time
from typing import Dict, List, Optional, Tuple
import numpy as np

from src.attacks.ground_truth import AttackEvent
from src.detection.decision_tree import CANFDDecisionTree


def compute_attack_detection_latency(
    attack_events: list[AttackEvent],
    timestamps_us: list[int],
    y_true: np.ndarray,
    y_pred: np.ndarray,
) -> dict[str, dict[str, float]]:
    """Compute simulation detection latency for each attack event.

    Args:
        attack_events: Registered ground truth attack events.
        timestamps_us: List of simulation timestamps in microseconds.
        y_true: Ground truth label array.
        y_pred: Predicted class label array.

    Returns:
        Mapping of attack name -> {start_ms, first_alert_ms, latency_ms, detected}.
    """
    results = {}

    for evt in attack_events:
        evt_type = evt.attack_type
        start_us = evt.start_us
        end_us = evt.end_us

        # Find first matching detection within or immediately following the attack window
        first_alert_us: Optional[int] = None
        for t_us, true_lbl, pred_lbl in zip(timestamps_us, y_true, y_pred):
            if t_us >= start_us and pred_lbl == evt_type:
                first_alert_us = t_us
                break

        if first_alert_us is not None:
            latency_ms = (first_alert_us - start_us) / 1000.0
            results[evt.name] = {
                "attack_type": evt_type,
                "start_ms": start_us / 1000.0,
                "first_alert_ms": first_alert_us / 1000.0,
                "latency_ms": round(latency_ms, 2),
                "detected": True,
            }
        else:
            results[evt.name] = {
                "attack_type": evt_type,
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
    """Measure real CPU inference time per frame in microseconds."""
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
