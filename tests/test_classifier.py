"""Unit and Integration Tests for Decision Tree Classifier and C Export Equivalence."""

import pytest
import numpy as np
from src.detection.decision_tree import CANFDDecisionTree, CLASS_NAMES
from src.detection.export_c import CCodeExporter


@pytest.fixture
def synthetic_dataset():
    # 6 classes: 0: Normal, 1: DoS, 2: Fuzzing, 3: Spoofing, 4: Replay, 5: Suppression
    np.random.seed(42)
    n_samples_per_class = 50
    X_list = []
    y_list = []

    for cls_idx in range(6):
        # 14 integer features
        data = np.random.randint(0, 100, size=(n_samples_per_class, 14), dtype=np.int64)
        if cls_idx == 1:  # DoS: high id_rate and total_bus_rate
            data[:, 5] += 200
            data[:, 6] += 500
        elif cls_idx == 2:  # Fuzzing: unseen ID or dlc mismatch
            data[:, 7] = 0  # id_seen_before = 0
            data[:, 8] = 1  # dlc_mismatch = 1
        elif cls_idx == 3:  # Spoofing: high period deviation and payload delta
            data[:, 4] += 15000
            data[:, 2] += 150
        elif cls_idx == 4:  # Replay: high replay similarity and duplicate count
            data[:, 12] = 1000
            data[:, 13] += 10
        elif cls_idx == 5:  # Suppression: missing_frame_count > 0 and large inter_arrival
            data[:, 11] += 5
            data[:, 3] += 250000

        X_list.append(data)
        y_list.append(np.full(n_samples_per_class, cls_idx, dtype=np.int64))

    X = np.vstack(X_list)
    y = np.concatenate(y_list)

    # Shuffle
    indices = np.arange(len(X))
    np.random.shuffle(indices)
    return X[indices], y[indices]


def test_decision_tree_training_and_inference(synthetic_dataset):
    X, y = synthetic_dataset
    split = int(0.7 * len(X))
    X_train, y_train = X[:split], y[:split]
    X_test, y_test = X[split:], y[split:]

    dt = CANFDDecisionTree(max_depth=6, random_state=42)
    dt.fit(X_train, y_train)

    preds = dt.predict(X_test)
    assert len(preds) == len(y_test)
    accuracy = float(np.mean(preds == y_test))
    assert accuracy >= 0.85


def test_c_export_equivalence(synthetic_dataset, tmp_path):
    X, y = synthetic_dataset
    dt = CANFDDecisionTree(max_depth=6, random_state=42)
    dt.fit(X, y)

    py_preds = dt.predict(X)

    exporter = CCodeExporter(dt)
    export_dir = str(tmp_path / "exported")
    agreement = exporter.compile_and_verify(X_test=X, y_expected=py_preds, output_dir=export_dir)

    # REQ-10: C inference and Python inference must agree on 100% of samples
    assert agreement == 1.0
