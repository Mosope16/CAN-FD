"""Tests for Long-Duration Simulation Stability and Memory Boundedness.

Validates that the CAN-FD feature extraction pipeline maintains bounded memory
usage (ring buffers, deques, sliding windows) and stable throughput across
longer simulation runs without buffer bloat or latency degradation.
"""

from __future__ import annotations

import time
import numpy as np
import pytest

from src.features.feature_pipeline import FeaturePipeline
from src.generator.traffic_generator import TrafficGenerator


def test_long_simulation_buffer_bounds() -> None:
    """Verify that buffer sizes remain strictly bounded over a 20-second simulation trace."""
    duration_ms = 20000  # 20 seconds
    traffic_gen = TrafficGenerator("configs/network.yaml", seed=123)
    frames = traffic_gen.generate_trace(duration_ms=duration_ms)

    assert len(frames) > 5000, f"Expected > 5000 frames in 20s trace, got {len(frames)}"

    pipeline = FeaturePipeline("configs/network.yaml", window_duration_ms=50, history_buffer_size=1000)

    t0 = time.perf_counter()
    X, y, timestamps = pipeline.process_trace(frames)
    t1 = time.perf_counter()

    elapsed = t1 - t0
    fps = len(frames) / elapsed
    assert fps > 20000, f"Sustained throughput degraded on long trace: {fps:.1f} fps"

    # 1. Output matrix shapes and integer validity
    assert X.shape == (len(frames), 14)
    assert not np.isnan(X).any(), "Found NaN in feature matrix."
    assert np.all(X <= np.iinfo(np.int64).max) and np.all(X >= np.iinfo(np.int64).min)

    # 2. Verify Sliding Window deque bounds (window is 50ms = 50,000 us)
    # The number of timestamps in the bus window at the end must be bounded by traffic in that 50ms
    assert len(pipeline.sliding_window.bus_timestamps) < 200, "Sliding window bus_timestamps exceeded upper bound."

    # 3. Verify per-ID deque bounds (history_buffer_size = 1000)
    for mid, q in pipeline.frame_monitor.payload_history.items():
        assert len(q) <= 1000, f"Payload history buffer for ID {hex(mid)} exceeded 1000 items: {len(q)}"

    # 4. Verify historical payload set is bounded
    for mid, s in pipeline.frame_monitor.historical_payload_set.items():
        assert len(s) <= 1000, f"Historical payload set for ID {hex(mid)} exceeded 1000 items: {len(s)}"
