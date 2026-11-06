"""Automated CAN-FD Dataset Generator.

Simulates realistic vehicular traffic and injects DoS, Fuzzing, Spoofing,
Replay, and Suppression attacks with strict ground-truth separation.
"""

from __future__ import annotations

import heapq
import os
import sys

# Ensure repository root is on Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from typing import Dict, List, Tuple
import numpy as np
import pandas as pd
import yaml

from src.attacks.dos import DoSAttack
from src.attacks.fuzzing import FuzzingAttack
from src.attacks.ground_truth import GroundTruthManager
from src.attacks.replay import ReplayAttack
from src.attacks.spoofing import SpoofingAttack
from src.attacks.suppression import SuppressionAttack
from src.features.feature_pipeline import FeaturePipeline
from src.features.frame_features import FEATURE_NAMES
from src.generator.message_definitions import load_network_config
from src.generator.traffic_generator import CANFDFrame, TrafficGenerator


def generate_simulation_episode(
    network_yaml: str = "configs/network.yaml",
    duration_ms: int = 10000,
    seed: int = 42,
) -> tuple[list[CANFDFrame], GroundTruthManager]:
    """Generate a chronological multi-attack CAN-FD simulation episode."""
    msg_defs = load_network_config(network_yaml)
    traffic_gen = TrafficGenerator(network_yaml, seed=seed)
    gt_mgr = GroundTruthManager()

    # 1. Define Suppression Attack (8000ms - 9200ms on 0x102 BrakeStatus)
    supp_attack = SuppressionAttack(target_id=0x102, start_ms=8000, duration_ms=1200)
    gt_mgr.register_event(
        attack_type=5,
        name="Suppression_Brake",
        target_id=0x102,
        start_ms=8000,
        duration_ms=1200,
        description="Suppression of periodic 0x102 BrakeStatus broadcasts",
    )

    # Generate baseline benign traffic with suppression hook
    benign_frames = traffic_gen.generate_trace(
        duration_ms=duration_ms,
        suppression_hooks=lambda t: {0x102} if supp_attack.is_suppressed(0x102, t) else set(),
    )

    # 2. Define DoS Flooding Attack (1000ms - 1800ms)
    dos_attack = DoSAttack(start_ms=1000, duration_ms=800, target_id=0x050, interval_us=500)
    dos_frames = dos_attack.generate_frames()
    gt_mgr.register_event(
        attack_type=1,
        name="DoS_Flood",
        target_id=0x050,
        start_ms=1000,
        duration_ms=800,
        description="High-priority 0x050 dominant ID flooding",
    )

    # 3. Define Fuzzing Attack (2500ms - 3500ms)
    fuzz_attack = FuzzingAttack(start_ms=2500, duration_ms=1000, interval_us=2000, seed=seed + 100)
    fuzz_frames = fuzz_attack.generate_frames()
    gt_mgr.register_event(
        attack_type=2,
        name="Fuzzing_Random",
        target_id=None,
        start_ms=2500,
        duration_ms=1000,
        description="Random ID and payload injection",
    )

    # 4. Define Spoofing Attack (4500ms - 5500ms on 0x102 BrakeStatus)
    brake_def = msg_defs[0x102]
    spoof_attack = SpoofingAttack.from_signals(
        start_ms=4500,
        duration_ms=1000,
        msg_def=brake_def,
        interval_us=7000,
        spoofed_signals={"pedal_pos_pct": 100.0, "pressure_bar": 220.0, "abs_active": 1.0},
    )
    spoof_frames = spoof_attack.generate_frames()
    gt_mgr.register_event(
        attack_type=3,
        name="Spoofing_Brake",
        target_id=0x102,
        start_ms=4500,
        duration_ms=1000,
        description="Counterfeit 0x102 BrakeStatus injection with maximum hydraulic pressure",
    )

    # 5. Define Replay Attack (6500ms - 7500ms on 0x103 SteeringAngle)
    replay_attack = ReplayAttack.capture_and_schedule(
        frames_pool=benign_frames,
        target_id=0x103,
        capture_start_ms=500,
        capture_duration_ms=1000,
        replay_start_ms=6500,
    )
    replay_frames = replay_attack.generate_frames()
    gt_mgr.register_event(
        attack_type=4,
        name="Replay_Steering",
        target_id=0x103,
        start_ms=6500,
        duration_ms=1000,
        description="Verbatim replay of previously captured 0x103 steering frames",
    )

    # Merge all frame streams and sort chronologically by timestamp_us
    all_frames = benign_frames + dos_frames + fuzz_frames + spoof_frames + replay_frames
    all_frames.sort(key=lambda f: f.timestamp_us)

    return all_frames, gt_mgr


def main() -> None:
    print("[+] Initializing CAN-FD multi-episode dataset generation...")
    os.makedirs("datasets/generated", exist_ok=True)
    os.makedirs("datasets/processed", exist_ok=True)

    # Generate chronologically separated episodes for train, validation, and test splits
    # Episode 1 (seed=42): Training split
    # Episode 2 (seed=101): Validation split
    # Episode 3 (seed=202): Test split
    episodes = [
        ("train", 42),
        ("val", 101),
        ("test", 202),
    ]

    for split_name, seed in episodes:
        print(f"[+] Generating episode for split: {split_name} (seed={seed})...")
        frames, gt_mgr = generate_simulation_episode(
            network_yaml="configs/network.yaml",
            duration_ms=10000,
            seed=seed,
        )

        pipeline = FeaturePipeline(network_config_path="configs/network.yaml", window_duration_ms=50)
        X, y, timestamps = pipeline.process_trace(frames)

        # Assemble DataFrame
        df = pd.DataFrame(X, columns=FEATURE_NAMES)
        df["label"] = y
        df["timestamp_us"] = timestamps

        csv_path = f"datasets/generated/{split_name}.csv"
        df.to_csv(csv_path, index=False)
        print(f"    Saved {len(df)} samples to {csv_path} (Class distribution: {dict(pd.Series(y).value_counts())})")

    print("[+] Dataset generation successfully completed.")


if __name__ == "__main__":
    main()
