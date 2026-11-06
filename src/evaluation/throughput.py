"""Simulation Processing Throughput Benchmark.

Measures the sustained frames-per-second throughput of the complete feature
extraction and classification pipeline to satisfy REQ-08.
"""

from __future__ import annotations

import time
from typing import Dict, List
import numpy as np

from src.detection.decision_tree import CANFDDecisionTree
from src.features.feature_pipeline import FeaturePipeline
from src.generator.traffic_generator import CANFDFrame


def benchmark_pipeline_throughput(
    frames: list[CANFDFrame],
    network_config_path: str,
    model: CANFDDecisionTree,
) -> dict[str, float]:
    """Measure total frames processed per second through feature extraction and model inference.

    Returns:
        Dictionary with frames_per_sec, total_frames, elapsed_sec, per_frame_overhead_us.
    """
    total_frames = len(frames)
    if total_frames == 0:
        return {"frames_per_sec": 0.0, "total_frames": 0, "elapsed_sec": 0.0}

    pipeline = FeaturePipeline(network_config_path=network_config_path)

    t_start = time.perf_counter()
    X, _, _ = pipeline.process_trace(frames)
    _ = model.predict(X)
    t_end = time.perf_counter()

    elapsed_sec = t_end - t_start
    fps = total_frames / elapsed_sec if elapsed_sec > 0 else 0.0
    per_frame_us = (elapsed_sec / total_frames) * 1_000_000.0 if total_frames > 0 else 0.0

    return {
        "frames_per_sec": round(fps, 1),
        "total_frames": total_frames,
        "elapsed_sec": round(elapsed_sec, 4),
        "per_frame_overhead_us": round(per_frame_us, 2),
    }
