"""Tests for Ground-Truth Decoupling and Zero Data Leakage.

Verifies that the feature extraction pipeline is strictly isolated from
ground-truth labels and attack metadata, ensuring identical feature outputs
even when labels and metadata are completely stripped or randomized.
"""

from __future__ import annotations

import copy
import numpy as np
import pytest

from scripts.generate_dataset import generate_simulation_episode
from src.features.feature_pipeline import FeaturePipeline
from src.generator.traffic_generator import CANFDFrame


def test_zero_ground_truth_leakage() -> None:
    """Verify that features are independent of frame.label and frame.attack_name."""
    frames, _ = generate_simulation_episode(
        network_yaml="configs/network.yaml",
        duration_ms=1000,
        seed=42,
    )

    pipeline_a = FeaturePipeline(network_config_path="configs/network.yaml")
    X_original, y_original, ts_original = pipeline_a.process_trace(frames)

    # Create sanitized frames where all labels and attack names are purged
    sanitized_frames = []
    for f in frames:
        sanitized = CANFDFrame(
            timestamp_us=f.timestamp_us,
            arbitration_id=f.arbitration_id,
            dlc=f.dlc,
            data=f.data,
            is_extended=f.is_extended,
            brs=f.brs,
            esi=f.esi,
            label=0,  # Zeroed out
            attack_name="NORMAL",  # Purged
        )
        sanitized_frames.append(sanitized)

    pipeline_b = FeaturePipeline(network_config_path="configs/network.yaml")
    X_sanitized, y_sanitized, ts_sanitized = pipeline_b.process_trace(sanitized_frames)

    # 1. Feature matrices must be bit-for-bit identical
    np.testing.assert_array_equal(
        X_original,
        X_sanitized,
        err_msg="Data leakage detected: feature values changed when labels/attack names were purged!",
    )

    # 2. Timestamps must be identical
    assert ts_original == ts_sanitized, "Timestamps diverged between original and sanitized traces."


def test_feature_pipeline_ignores_metadata_attributes() -> None:
    """Verify feature pipeline functions properly on objects with no attack attributes."""
    pipeline = FeaturePipeline(network_config_path="configs/network.yaml")

    class BareFrame:
        def __init__(self, t_us: int, aid: int, dlc: int, data: bytes):
            self.timestamp_us = t_us
            self.arbitration_id = aid
            self.dlc = dlc
            self.data = data
            self.is_extended = False
            self.brs = True
            self.esi = False
            self.label = 0

    bare_frames = [
        BareFrame(10000, 0x100, 8, b"\x01\x02\x03\x04\x05\x06\x07\x08"),
        BareFrame(20000, 0x100, 8, b"\x01\x02\x03\x04\x05\x06\x07\x09"),
    ]

    X, labels, ts = pipeline.process_trace(bare_frames)  # type: ignore[arg-type]
    assert X.shape == (2, 14)
    assert len(ts) == 2
