# CAN-FD Bit-Stream Intrusion Detection System (IDS)
**Machine-Learning-Assisted Automotive Attack Classifier & ISO/SAE 21434 Verification Pack**

---

## 1. Project Overview

This repository implements a modular, high-throughput, software-based **CAN-FD Bit-Stream Intrusion Detection System (IDS)** with embedded-friendly Machine Learning attack classification.

Unlike conventional CAN IDSs that only examine high-level arbitration IDs, this system models the full **ISO 11898-1:2015 CAN-FD physical bit-stream layer**, distinguishing between **physical protocol corruption** (CRC errors, dynamic stuff violations, fixed stuff bit inversions, ACK delimiter faults) and **syntactically valid behavioral cyberattacks** (DoS flooding, bus fuzzing, spoofing, replay, and targeted ECU suppression).

### Key Technical Contributions
* **Physical Bit-Stream Engine:** Implements dynamic bit-stuffing, ISO CRC-17 (DLC $\le 10$) and CRC-21 (DLC $> 10$), 3-bit Gray Stuff Counter with parity, and deterministic 4-bit fixed stuff bits.
* **Dual-Rate Bit Timing Model:** Accounts for nominal arbitration phase (500 kbps, $2.0\ \mu\text{s}$/bit) and high-speed data phase (2.0 Mbps, $0.5\ \mu\text{s}$/bit) transitioned via BRS.
* **Zero Floating-Point Feature Engine:** Extracts a 14-element fixed-point integer feature vector per frame/event, ensuring zero FPU latency on automotive microcontrollers.
* **Supervisory Message Suppression Detection:** Tracks expected periodic arrival deadlines, identifying ECU silencing attacks within $< 30$ ms.
* **Embedded ANSI C Inference:** Automatically compiles trained decision trees into pure C code (`classify_frame(...)`) with **100% equivalence** to Python scikit-learn inference.
* **ISO/SAE 21434 Alignment:** Complete Threat Analysis and Risk Assessment (TARA), verifiable cybersecurity requirements (REQ-01 to REQ-10), and automated traceability matrix.

---

## 2. ISO/SAE 21434 Requirements Verification Status

| Requirement ID | Threat Scenario | Verification Method | Initial Target Metric | Actual Result | Status |
|:---:|:---|:---|:---|:---:|:---:|
| **REQ-01** | Denial of Service (DoS) | Detection Latency Benchmark | Latency $\le 50$ ms | **$0.50$ ms** | **PASS** |
| **REQ-02** | Bus Fuzzing | Classification Recall | Recall $\ge 95\%$ | **$100.00\%$** | **PASS** |
| **REQ-03** | Spoofing / Masquerade | Classification Recall | Recall $\ge 90\%$ | **$97.90\%$** | **PASS** |
| **REQ-04** | Message Replay | Classification Recall | Recall $\ge 90\%$ | **$94.00\%$** | **PASS** |
| **REQ-05** | Message Suppression | Deadline Monitor Latency | Latency $\le 100$ ms | **$29.94$ ms** | **PASS** |
| **REQ-06** | Protocol Corruption | Physical Disturbance and DLC Boundary Suite | $100\%$ of defined test cases | **$100.0\%$** ($6/6$) | **PASS** |
| **REQ-07** | False Alarms | Benign Traffic Evaluation | False Positive Rate $< 1.0\%$ | **$0.470\%$** | **PASS** |
| **REQ-08** | Throughput & Overhead | Sustained Execution Benchmark | $\ge 10,000$ frames/sec | **$55,615.9$ fps** | **PASS** |
| **REQ-09** | Reproducibility | Multi-Run Bit-for-Bit Hash | $100\%$ identical output | **$100.0\%$** | **PASS** |
| **REQ-10** | Target Conformance | GCC Compiled C Conformance | $100\%$ prediction agreement | **$100.00\%$** | **PASS** |

---

## 3. Architecture & Repository Structure

```
canfd-ids/
├── configs/
│   ├── simulation.yaml            # Global simulation, clockwork, and bitrate configuration
│   ├── network.yaml               # Synthetic automotive DBC message & signal schemas
│   └── attacks.yaml               # Attack schedules, injection parameters, and corruption suite
├── docs/
│   ├── item-definition.md         # ISO 21434 Clause 9 Item Definition
│   ├── tara.md                    # ISO 21434 Clause 15 Threat Analysis and Risk Assessment
│   ├── requirements.md            # Cybersecurity Requirements (REQ-01 to REQ-10)
│   ├── architecture.md            # System Architecture and Subsystem Specifications
│   ├── verification-plan.md       # Verification & Validation Plan (TST-001 to TST-010)
│   └── traceability-matrix.csv    # Traceability matrix mapping threats to verified results
├── src/
│   ├── generator/                 # Traffic generation, DBC loading, and continuous physics models
│   ├── attacks/                   # DoS, Fuzzing, Spoofing, Replay, and Suppression engines
│   ├── protocol/                  # Bit-stream framing, bit-stuffing, CRC-17/21, and corruption injection
│   ├── monitor/                   # Per-ID baseline tracking and missing message deadline supervisor
│   ├── features/                  # Integer feature pipeline and sliding-window rate aggregator
│   ├── detection/                 # Decision Tree model, training, hyperparameter tuning, and C exporter
│   └── evaluation/                # Performance metrics, latency benchmarking, and throughput counters
├── datasets/generated/            # Chronologically separated datasets (train.csv, val.csv, test.csv)
├── models/
│   ├── decision_tree.pkl          # Serialized scikit-learn model artifact
│   └── exported/                  # Autogenerated ANSI C files (classifier.c, classifier.h, test_harness.c)
├── results/
│   ├── metrics/                   # JSON evaluation metrics and verification dumps
│   ├── graphs/                    # Confusion matrix and ablation study PNG plots
│   └── reports/                   # Comprehensive evaluation reports and simulation summaries
├── scripts/
│   ├── generate_dataset.py        # Generates multi-episode training, validation, and test datasets
│   ├── run_simulation.py          # Live end-to-end simulation runner with bit-stream validation
│   └── run_evaluation.py          # Full verification suite checking REQ-01 through REQ-10
├── tests/                         # Unit and integration test suite (40 tests)
├── requirements.txt               # Python package dependencies
└── README.md                      # Engineering documentation
```

---

## 4. Quickstart and Execution Guide

### 4.1 Prerequisites
* Linux environment (Arch / Ubuntu / Debian / Fedora)
* Python 3.10+ (tested on Python 3.14)
* GCC (for target C model compilation)
* Virtual environment with packages from `requirements.txt`

### 4.2 Installation
```bash
# Set up virtual environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 4.3 Generating Synthetic Datasets
Generates three chronologically independent episodes (train, val, test) ensuring zero data leakage:
```bash
PYTHONPATH=. python3 scripts/generate_dataset.py
```

### 4.4 Running Live Simulation Demonstration
Demonstrates physical bit-stream serialization, deliberate protocol corruptions, and real-time detection:
```bash
PYTHONPATH=. python3 scripts/run_simulation.py
```

### 4.5 Running Full ISO 21434 Verification Suite
Executes end-to-end evaluation, tunes tree depth, tests REQ-01..10, runs ablation studies, exports C code, and updates the traceability matrix:
```bash
PYTHONPATH=. python3 scripts/run_evaluation.py
```

### 4.6 Running Automated Unit Tests
```bash
pytest tests/
```

---

## 5. Embedded ANSI C Export

The Decision Tree classifier is automatically exported to pure ANSI C (`models/exported/classifier.c`):

```c
#include "classifier.h"

int classify_frame(int64_t frame_id, int64_t frame_dlc, int64_t payload_delta,
                   int64_t inter_arrival, int64_t period_deviation, int64_t id_rate,
                   int64_t total_bus_rate, int64_t id_seen_before, int64_t dlc_mismatch,
                   int64_t payload_change_count, int64_t protocol_error_count,
                   int64_t missing_frame_count, int64_t replay_similarity,
                   int64_t duplicate_count) {
    const int64_t f[14] = {frame_id, frame_dlc, payload_delta, inter_arrival,
                           period_deviation, id_rate, total_bus_rate, id_seen_before,
                           dlc_mismatch, payload_change_count, protocol_error_count,
                           missing_frame_count, replay_similarity, duplicate_count};
    return classify_frame_array(f);
}
```

Compile standalone C binary:
```bash
gcc -O2 models/exported/classifier.c models/exported/test_harness.c -o models/exported/c_classifier
```
The compiled C classifier runs in $< 220\ \text{ns}$ per frame with zero dynamic memory allocation.

---

## 6. Engineering Evidence Pack Deliverables

1. [Item Definition](docs/item-definition.md)
2. [Threat Analysis and Risk Assessment (TARA)](docs/tara.md)
3. [Cybersecurity Requirements Specification](docs/requirements.md)
4. [System Architecture & Design](docs/architecture.md)
5. [Verification & Validation Plan](docs/verification-plan.md)
6. [Traceability Matrix CSV](docs/traceability-matrix.csv)
7. [Comprehensive Evaluation Evidence Report](results/reports/evaluation_report.md)
8. [Simulation Summary JSON](results/reports/simulation_summary.json)
9. [Confusion Matrix Heatmap](results/graphs/confusion_matrix.png)
10. [Feature Ablation Plot](results/graphs/ablation_study.png)
11. [Report-facing Test CSV](results/report_data/canfd_test_frames.csv)
12. [ROC Curves](results/graphs/roc_curves.png)
13. [False Positives versus Bus Load](results/graphs/false_positives_vs_bus_load.png)
14. [Tree Complexity versus Depth](results/graphs/tree_complexity_vs_depth.png)
# CAN-FD
