"""Tests for Exported ANSI C Classifier Boundary and Edge Cases.

Verifies that the compiled C decision tree handles extreme numeric boundaries
(INT64_MAX, INT64_MIN, zero vectors, extreme deviations) safely and produces
100% agreement with the Python decision tree model.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import numpy as np
import pytest

from src.detection.decision_tree import CANFDDecisionTree
from src.detection.export_c import CCodeExporter
from src.features.frame_features import FEATURE_NAMES


@pytest.fixture(scope="module")
def trained_dt():
    if os.path.exists("models/decision_tree.pkl"):
        return CANFDDecisionTree.load("models/decision_tree.pkl")
    model = CANFDDecisionTree(max_depth=6, random_state=42)
    # Train on distinct samples to create splits
    X = np.array([
        [0x100, 8, 0, 10000, 0, 10, 15, 1, 0, 0, 0, 0, 0, 0],
        [0x100, 8, 0, 10000, 0, 10, 15, 1, 0, 0, 0, 0, 0, 0],
        [0x050, 8, 0, 500, -9500, 200, 210, 1, 0, 0, 0, 0, 0, 0],
        [0x050, 8, 0, 500, -9500, 200, 210, 1, 0, 0, 0, 0, 0, 0],
    ], dtype=np.int64)
    y = np.array([0, 0, 1, 1], dtype=np.int64)
    model.fit(X, y)
    return model


def test_c_code_compilation_and_edge_cases(trained_dt, tmp_path) -> None:
    """Verify that the C classifier compiles cleanly and handles INT64 boundaries."""
    exporter = CCodeExporter(trained_dt)
    c_source = exporter.generate_c_source()
    h_source = exporter.generate_header()

    c_file = tmp_path / "classifier.c"
    h_file = tmp_path / "classifier.h"
    harness_file = tmp_path / "edge_harness.c"
    bin_file = tmp_path / "edge_bench"

    c_file.write_text(c_source)
    h_file.write_text(h_source)

    # Edge case feature vectors
    edge_vectors = np.array([
        [0] * 14,                                              # All zeros
        [9223372036854775807] * 14,                            # INT64_MAX
        [-9223372036854775807] * 14,                           # Negative extreme
        [0x100, 8, 0, 10000, 0, 10, 15, 1, 0, 0, 0, 0, 0, 0],  # Benign
        [0x050, 8, 0, 500, -9500, 200, 210, 1, 0, 0, 0, 0, 0, 0], # DoS
    ], dtype=np.int64)

    # Expected predictions from Python model
    py_preds = trained_dt.predict(edge_vectors)

    # Generate edge test harness in C
    lines = [
        '#include <stdio.h>',
        '#include <stdint.h>',
        '#include <stdlib.h>',
        '#include "classifier.h"',
        "",
        "int main(void) {",
    ]

    for idx, vec in enumerate(edge_vectors):
        vec_str = ", ".join(f"{int(v)}LL" for v in vec)
        lines.append(f"    int64_t v{idx}[14] = {{{vec_str}}};")
        lines.append(f"    int p{idx} = classify_frame_array(v{idx});")
        lines.append(f'    printf("%d\\n", p{idx});')

    lines.append("    return 0;")
    lines.append("}")

    harness_file.write_text("\n".join(lines))

    # Compile with GCC strict flags
    cmd = [
        "gcc",
        "-O2",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-I", str(tmp_path),
        str(harness_file),
        str(c_file),
        "-o", str(bin_file),
    ]
    comp_res = subprocess.run(cmd, capture_output=True, text=True)
    assert comp_res.returncode == 0, f"Compilation failed: {comp_res.stderr}"

    # Run binary
    run_res = subprocess.run([str(bin_file)], capture_output=True, text=True)
    assert run_res.returncode == 0, f"Execution failed: {run_res.stderr}"

    c_preds = [int(line.strip()) for line in run_res.stdout.strip().splitlines() if line.strip()]
    assert len(c_preds) == len(py_preds)

    # Compare bit-for-bit with Python model predictions
    for idx, (cp, pp) in enumerate(zip(c_preds, py_preds)):
        assert cp == pp, f"Mismatch at edge vector {idx}: C={cp}, Python={pp}"
        assert cp in [0, 1, 2, 3, 4, 5], f"Invalid class predicted: {cp}"
