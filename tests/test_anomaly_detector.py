"""Tests for Complementary Normal-Only Anomaly Detector.

Validates fitting on benign telemetry, isolation-based outlier detection,
deterministic envelope checks, and serialization.
"""

from __future__ import annotations

import os
import numpy as np
import pytest

from src.detection.anomaly_detector import NormalTrafficAnomalyDetector
from src.features.frame_features import FEATURE_NAMES


@pytest.fixture
def dummy_normal_data():
    np.random.seed(42)
    # 500 samples of normal features:
    # frame_id (0x100), frame_dlc (8), payload_delta (0-5), inter_arr (~10000 us),
    # period_dev (~0 us), id_rate (~10), bus_rate (~15), id_seen (1), dlc_mis (0),
    # p_change (0-2), proto_err (0), missing (0), replay_sim (0), dup_cnt (0)
    data = []
    for _ in range(500):
        row = [
            0x100,
            8,
            np.random.randint(0, 5),
            10000 + np.random.randint(-50, 50),
            np.random.randint(-50, 50),
            10,
            15,
            1,
            0,
            np.random.randint(0, 2),
            0,
            0,
            0,
            0,
        ]
        data.append(row)
    return np.array(data, dtype=np.int64)


def test_anomaly_detector_lifecycle(dummy_normal_data, tmp_path) -> None:
    """Verify fit, save, load, and anomalous prediction boundaries."""
    ad = NormalTrafficAnomalyDetector(contamination=0.01, random_state=42)

    with pytest.raises(RuntimeError):
        ad.predict_anomaly(dummy_normal_data[:10])

    ad.fit(dummy_normal_data)
    assert ad.is_fitted
    assert ad.max_bus_rate == 15

    # 1. Benign normal test samples should mostly have label 0
    normal_preds = ad.predict_anomaly(dummy_normal_data)
    assert np.mean(normal_preds == 0) > 0.98

    # 2. Test Unseen CAN ID (id_seen_before == 0) -> Must flag as 1
    unseen_id_row = dummy_normal_data[0].copy()
    unseen_id_row[FEATURE_NAMES.index("id_seen_before")] = 0
    pred = ad.predict_anomaly(unseen_id_row.reshape(1, -1))
    assert pred[0] == 1

    # 3. Test DLC Mismatch -> Must flag as 1
    dlc_mis_row = dummy_normal_data[0].copy()
    dlc_mis_row[FEATURE_NAMES.index("dlc_mismatch")] = 1
    pred = ad.predict_anomaly(dlc_mis_row.reshape(1, -1))
    assert pred[0] == 1

    # 4. Test Bus Rate Surge (DoS Flood: bus_rate = 100 >> 15 * 1.5) -> Must flag as 1
    flood_row = dummy_normal_data[0].copy()
    flood_row[FEATURE_NAMES.index("total_bus_rate")] = 100
    pred = ad.predict_anomaly(flood_row.reshape(1, -1))
    assert pred[0] == 1

    # 5. Serialization and Deserialization
    save_path = str(tmp_path / "ad_test.pkl")
    ad.save(save_path)
    loaded_ad = NormalTrafficAnomalyDetector.load(save_path)
    assert loaded_ad.is_fitted
    np.testing.assert_array_equal(loaded_ad.predict_anomaly(dummy_normal_data[:20]), ad.predict_anomaly(dummy_normal_data[:20]))
