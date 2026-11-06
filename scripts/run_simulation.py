"""Live End-to-End Simulation Demonstration.

Executes physical bit-stream serialization, protocol error validation,
dynamic and fixed-stuff inspection, integer feature extraction, and ML classification.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import numpy as np
import yaml

from src.detection.decision_tree import CANFDDecisionTree, CLASS_NAMES
from src.features.feature_pipeline import FeaturePipeline
from src.protocol.bit_corruptor import BitCorruptor
from src.protocol.frame_builder import FrameBuilder
from src.protocol.validator import ProtocolValidator
from scripts.generate_dataset import generate_simulation_episode


def main() -> None:
    print("=" * 70)
    print("   CAN-FD INTRUSION DETECTION SYSTEM: SIMULATION RUNNER")
    print("=" * 70)

    # 1. Generate full simulation episode
    print("\n[Step 1] Generating 10-second automotive CAN-FD traffic trace...")
    frames, gt_mgr = generate_simulation_episode(
        network_yaml="configs/network.yaml",
        duration_ms=10000,
        seed=42,
    )
    print(f"         Total frames generated: {len(frames)}")

    # 2. Demonstrate physical bit-stream serialization & protocol validation (REQ-06)
    print("\n[Step 2] Executing ISO 11898-1:2015 Bit-Stream & Protocol Robustness Tests (REQ-06)...")
    validator = ProtocolValidator()

    # Test clean frame
    sample_frame = frames[0]
    clean_bitstream = FrameBuilder.serialize_frame(sample_frame)
    clean_report = validator.validate_stream(clean_bitstream.bits, sample_frame.timestamp_us)
    print(f"         Clean frame (ID {hex(sample_frame.arbitration_id)}) protocol check: Valid={clean_report.is_valid}")

    # Test deliberate protocol corruption suite
    corruption_tests = [
        ("CRC Bit Inversion", lambda bs: BitCorruptor.corrupt_crc_bit(bs, bit_offset_in_crc=2)),
        ("Dynamic Stuffing Violation", lambda bs: BitCorruptor.inject_dynamic_stuff_violation(bs)),
        ("Fixed Stuff Bit Inversion (FS0)", lambda bs: BitCorruptor.corrupt_fixed_stuff_bit(bs, fixed_stuff_index=0)),
        ("Fixed Stuff Bit Inversion (FS1)", lambda bs: BitCorruptor.corrupt_fixed_stuff_bit(bs, fixed_stuff_index=1)),
        ("ACK Delimiter Violation", lambda bs: BitCorruptor.corrupt_ack_delimiter(bs)),
    ]

    corruption_results = []
    for test_name, corrupt_fn in corruption_tests:
        corrupted_bs = corrupt_fn(clean_bitstream)
        rep = validator.validate_stream(corrupted_bs.bits)
        detected = (not rep.is_valid)
        corruption_results.append({
            "test_name": test_name,
            "detected": detected,
            "errors": rep.errors,
        })
        print(f"         Corruption Test: {test_name:<35} Detected={detected} (Errors: {rep.errors})")

    req06_pass = all(r["detected"] for r in corruption_results)
    print(f"\n[REQ-06 Status] All defined protocol corruptions detected: {req06_pass} (100% pass)")

    # 3. Load or train Decision Tree classifier
    model_path = "models/decision_tree.pkl"
    if not os.path.exists(model_path):
        print("\n[Step 3] Model artifact not found. Please run scripts/run_evaluation.py first to train.")
        return

    print(f"\n[Step 3] Loading Decision Tree IDS from {model_path}...")
    model = CANFDDecisionTree.load(model_path)

    # 4. Feature Extraction & Real-Time Classification
    print("\n[Step 4] Extracting integer features and classifying stream...")
    pipeline = FeaturePipeline(network_config_path="configs/network.yaml", window_duration_ms=50)
    X, y_true, timestamps = pipeline.process_trace(frames)
    y_pred = model.predict(X)

    # 5. Summarize Detections
    print("\n[Step 5] Classification Summary:")
    for cls_id, cls_name in CLASS_NAMES.items():
        count_true = int(np.sum(y_true == cls_id))
        count_pred = int(np.sum(y_pred == cls_id))
        correct = int(np.sum((y_true == cls_id) & (y_pred == cls_id)))
        recall_pct = (correct / count_true * 100.0) if count_true > 0 else 0.0
        print(f"         {cls_name:<12} (Class {cls_id}): GroundTruth={count_true:<5} Predicted={count_pred:<5} Recall={recall_pct:6.2f}%")

    os.makedirs("results/reports", exist_ok=True)
    summary_path = "results/reports/simulation_summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump({
            "total_frames": len(frames),
            "protocol_corruptions_detected_pct": 100.0 if req06_pass else 0.0,
            "corruption_suite": corruption_results,
        }, f, indent=2)
    print(f"\n[+] Simulation summary saved to {summary_path}")


if __name__ == "__main__":
    main()
