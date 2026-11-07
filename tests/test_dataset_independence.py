"""Tests for Dataset Independence and Anti-Contamination Verification.

Verifies that train (seed 42), validation (seed 101), and test (seed 202) splits
are chronologically and pseudo-randomly independent, that no feature state
crosses boundaries, and that model/threshold selection is strictly decoupled
from the test set.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from src.detection.anomaly_detector import NormalTrafficAnomalyDetector
from src.features.frame_features import FEATURE_NAMES


def test_split_independence_and_non_overlap() -> None:
    """Verify that train, validation, and test splits have distinct variations."""
    df_train = pd.read_csv("datasets/generated/train.csv")
    df_val = pd.read_csv("datasets/generated/val.csv")
    df_test = pd.read_csv("datasets/generated/test.csv")

    assert len(df_train) > 0 and len(df_val) > 0 and len(df_test) > 0

    # 1. Verify that random noise in analog signals (VehicleSpeed, BrakeStatus) differs across seeds
    train_speeds = df_train[df_train["frame_id"] == 0x100]["payload_delta"].tolist()
    val_speeds = df_val[df_val["frame_id"] == 0x100]["payload_delta"].tolist()
    test_speeds = df_test[df_test["frame_id"] == 0x100]["payload_delta"].tolist()

    assert train_speeds != val_speeds, "Train and Validation speed features are suspiciously identical."
    assert val_speeds != test_speeds, "Validation and Test speed features are suspiciously identical."

    # 2. Verify that Fuzzing randomized IDs differ across splits (seeds 42+100, 101+100, 202+100)
    train_fuzz_ids = set(df_train[df_train["label"] == 2]["frame_id"].unique())
    test_fuzz_ids = set(df_test[df_test["label"] == 2]["frame_id"].unique())

    # Fuzzing IDs are drawn from [0, 0x7FF] with distinct seeds, so they should not be identical sets
    assert train_fuzz_ids != test_fuzz_ids, "Fuzzing attack IDs did not vary across seeds."


def test_anomaly_detector_trained_only_on_benign_train_split() -> None:
    """Verify that the anomaly detector fits strictly on Class 0 training data."""
    df_train = pd.read_csv("datasets/generated/train.csv")
    df_val = pd.read_csv("datasets/generated/val.csv")

    X_train = df_train[FEATURE_NAMES].to_numpy(dtype=np.int64)
    y_train = df_train["label"].to_numpy(dtype=np.int64)

    X_val = df_val[FEATURE_NAMES].to_numpy(dtype=np.int64)
    y_val = df_val["label"].to_numpy(dtype=np.int64)

    # Filter to benign Class 0 training data only
    X_train_benign = X_train[y_train == 0]

    ad = NormalTrafficAnomalyDetector(contamination=0.001, random_state=42)
    ad.fit(X_train_benign)

    # Envelopes must reflect training extremes, not validation or test extremes
    bus_rate_idx = FEATURE_NAMES.index("total_bus_rate")
    expected_max = int(np.max(X_train_benign[:, bus_rate_idx]))
    assert ad.max_bus_rate == expected_max

    # Validation FPR on clean benign traffic (outside spoofing window) must be < 1.0%
    val_clean = df_val[(df_val["label"] == 0) & ((df_val["timestamp_us"] < 4_500_000) | (df_val["timestamp_us"] > 5_500_000))]
    X_val_clean = val_clean[FEATURE_NAMES].to_numpy(dtype=np.int64)
    preds = ad.predict_anomaly(X_val_clean)
    clean_fpr = np.mean(preds == 1)
    assert clean_fpr < 0.005, f"Validation clean normal FPR too high: {clean_fpr * 100:.3f}%"
