"""Tests for Mixed and Concurrent Automotive Attack Scenarios.

Validates that the CAN-FD IDS and Feature Extraction Pipeline handle overlapping,
concurrent attack injections (e.g., DoS bus flooding simultaneous with Spoofing
or Fuzzing) without state corruption or pipeline failure.
"""

from __future__ import annotations

import numpy as np
import pytest

from src.attacks.dos import DoSAttack
from src.attacks.fuzzing import FuzzingAttack
from src.attacks.spoofing import SpoofingAttack
from src.detection.decision_tree import CANFDDecisionTree
from src.features.feature_pipeline import FeaturePipeline
from src.features.frame_features import FEATURE_NAMES
from src.generator.message_definitions import load_network_config
from src.generator.traffic_generator import TrafficGenerator


def test_concurrent_dos_and_spoofing() -> None:
    """Verify that concurrent DoS flooding and counterfeit Spoofing are handled robustly."""
    traffic_gen = TrafficGenerator("configs/network.yaml", seed=777)
    benign_frames = traffic_gen.generate_trace(duration_ms=2000)

    # Injected concurrent attacks: DoS flood (0x050) from 500ms to 1500ms
    dos = DoSAttack(start_ms=500, duration_ms=1000, target_id=0x050, interval_us=1000)
    dos_frames = dos.generate_frames()

    # Concurrent Spoofing on 0x102 (BrakeStatus) from 800ms to 1400ms (overlapping window)
    msg_defs = load_network_config("configs/network.yaml")
    spoof = SpoofingAttack.from_signals(
        start_ms=800,
        duration_ms=600,
        msg_def=msg_defs[0x102],
        interval_us=7000,
        spoofed_signals={"pedal_pos_pct": 100.0, "pressure_bar": 200.0, "abs_active": 1.0},
    )
    spoof_frames = spoof.generate_frames()

    # Merge and sort chronologically
    mixed_stream = benign_frames + dos_frames + spoof_frames
    mixed_stream.sort(key=lambda f: f.timestamp_us)

    pipeline = FeaturePipeline("configs/network.yaml")
    X, y, timestamps = pipeline.process_trace(mixed_stream)

    # Assert matrix dimensions
    assert X.shape[0] == len(mixed_stream)
    assert X.shape[1] == 14

    # Load trained model if available, else test pipeline outputs
    model = CANFDDecisionTree.load("models/decision_tree.pkl")
    preds = model.predict(X)

    # Verify detection inside the concurrent attack interval [800ms, 1400ms]
    concurrent_mask = (np.array(timestamps) >= 800_000) & (np.array(timestamps) <= 1_400_000)
    concurrent_y = y[concurrent_mask]
    concurrent_preds = preds[concurrent_mask]

    # In concurrent window, attack frames should be detected as non-zero (non-normal)
    malicious_in_window = (concurrent_y != 0)
    flagged_in_window = (concurrent_preds != 0)
    attack_recall = np.sum(flagged_in_window & malicious_in_window) / np.sum(malicious_in_window)

    assert attack_recall > 0.95, f"Expected > 95% detection in concurrent attack window, got {attack_recall * 100:.2f}%"


def test_concurrent_fuzzing_and_suppression() -> None:
    """Verify concurrent randomized fuzzing during message suppression."""
    traffic_gen = TrafficGenerator("configs/network.yaml", seed=888)
    benign_frames = traffic_gen.generate_trace(
        duration_ms=2000,
        suppression_hooks=lambda t: {0x102} if (500_000 <= t <= 1_500_000) else set(),
    )

    fuzz = FuzzingAttack(start_ms=700, duration_ms=600, interval_us=2000, seed=999)
    fuzz_frames = fuzz.generate_frames()

    mixed_stream = benign_frames + fuzz_frames
    mixed_stream.sort(key=lambda f: f.timestamp_us)

    pipeline = FeaturePipeline("configs/network.yaml")
    X, y, timestamps = pipeline.process_trace(mixed_stream)

    # Verify suppression entries were generated despite concurrent fuzzing
    suppression_count = np.sum(y == 5)
    assert suppression_count > 0, "Suppression events were missed during concurrent fuzzing."
