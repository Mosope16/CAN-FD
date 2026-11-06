"""Unit tests for Integer Feature Extraction Pipeline."""

import pytest
import numpy as np
from src.features.feature_pipeline import FeaturePipeline
from src.features.frame_features import FEATURE_NAMES
from src.generator.traffic_generator import CANFDFrame, TrafficGenerator


def test_feature_pipeline_shape_and_types():
    gen = TrafficGenerator("configs/network.yaml", seed=42)
    frames = gen.generate_trace(duration_ms=500)
    assert len(frames) > 0

    pipeline = FeaturePipeline("configs/network.yaml", window_duration_ms=50)
    X, y, timestamps = pipeline.process_trace(frames)

    assert isinstance(X, np.ndarray)
    assert isinstance(y, np.ndarray)
    assert X.ndim == 2
    assert X.shape[1] == len(FEATURE_NAMES)
    assert X.shape[1] == 14
    assert X.dtype == np.int64
    assert y.dtype == np.int64
    assert len(X) == len(y)
    assert len(X) >= len(frames)


def test_feature_pipeline_missing_deadline():
    # If a periodic ID is never received, supervisor should detect missing deadline
    frames = [
        CANFDFrame(timestamp_us=0, arbitration_id=0x100, dlc=8, data=b"speed000"),
        # Jump ahead 500ms (500,000 us). Expected period of 0x100 is 10ms (10,000us).
        CANFDFrame(timestamp_us=500_000, arbitration_id=0x100, dlc=8, data=b"speed001"),
    ]
    pipeline = FeaturePipeline("configs/network.yaml", window_duration_ms=50)
    X, y, timestamps = pipeline.process_trace(frames)

    # Should have generated missing-frame events with label 5 (Suppression)
    assert 5 in y
    supp_indices = np.where(y == 5)[0]
    assert len(supp_indices) > 0
    # For suppression events, missing_frame_count > 0 or inter_arrival large
    assert any(X[idx, 11] > 0 or X[idx, 3] > 20_000 for idx in supp_indices)
