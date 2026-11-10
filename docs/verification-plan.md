# Verification and Validation Plan
**Standard Alignment:** ISO/SAE 21434:2021, Clause 11 & 14

---

## 1. Scope & Objective
This Verification and Validation (V&V) plan outlines the testing framework designed to demonstrate that the CAN-FD Bit-Stream IDS satisfies all security and operational requirements (REQ-01 to REQ-10) established during the TARA phase.

Testing is divided into:
1. **Unit Verification:** Protocol bit-stuffing, CRC-17/21 computation, ISO stuff count parity, and logical frame decoding.
2. **Behavioral Security Testing:** Detection latency and classification metrics across DoS, fuzzing, spoofing, replay, and suppression attacks.
3. **Protocol Robustness Testing:** Exhaustive validation of bit-level corruption patterns.
4. **Target Conformance Testing:** Bit-for-bit prediction equivalence between Python scikit-learn models and the exported ANSI C decision tree.

---

## 2. Test Procedures and Acceptance Criteria

### TST-001: Denial of Service Detection Latency
* **Target Requirement:** REQ-01
* **Preconditions:** Network baseline loaded; sliding window configured at 50ms/100ms.
* **Input Scenario:** Inject high-frequency dominant ID `0x050` frames every 500 $\mu$s starting at $T=1000$ ms.
* **Expected Result:** Sliding window total bus rate and per-ID rate surge; classifier issues first DoS alert before $T=1050$ ms.
* **Pass Criteria:** Latency $(T_{\text{first\_alert}} - T_{\text{attack\_start}}) \le 50.0$ ms.

### TST-002: Fuzzing Attack Classification Recall
* **Target Requirement:** REQ-02
* **Preconditions:** Feature extractor initialized with configured DBC message map.
* **Input Scenario:** Inject randomized identifiers (in range 0x000-0x7FF), anomalous DLCs, and pseudorandom payload bytes.
* **Expected Result:** Unseen IDs and DLC mismatches correctly labeled as Fuzzing.
* **Pass Criteria:** Recall $\ge 95.0\%$.

### TST-003: Spoofing Attack Classification Recall
* **Target Requirement:** REQ-03
* **Preconditions:** Baseline periodic rates and signal ranges calibrated.
* **Input Scenario:** Transmit counterfeit `0x102` BrakeStatus frames at irregular intervals (7ms instead of 20ms) with out-of-bounds sensor readings.
* **Expected Result:** Period deviation and payload gradient features detect spoofed frames.
* **Pass Criteria:** Recall $\ge 90.0\%$.

### TST-004: Replay Attack Classification Recall
* **Target Requirement:** REQ-04
* **Preconditions:** Historical payload circular buffer active.
* **Input Scenario:** Capture genuine SteeringAngle frames from $T=[500, 1500]$ ms and replay them at $T=[6500, 7500]$ ms.
* **Expected Result:** Replay similarity metric and zero payload delta trigger Replay alert.
* **Pass Criteria:** Recall $\ge 90.0\%$.

### TST-005: Suppression Attack Detection Latency
* **Target Requirement:** REQ-05
* **Preconditions:** Missing Message Supervisor active with expected deadlines configured.
* **Input Scenario:** Silence periodic transmission of `0x102` BrakeStatus (period 20ms) starting at $T=8000$ ms.
* **Expected Result:** Supervisor deadline expires at $T=8000 + (1.5 \times 20) = 8030$ ms; alert generated on the next bus tick.
* **Pass Criteria:** $(T_{\text{alert}} - T_{\text{deadline}}) \le 100.0$ ms.

### TST-006: Bit Corruption Protocol Verification
* **Target Requirement:** REQ-06
* **Preconditions:** Frame builder, CRC engine, bit stuffer, and protocol validator initialized.
* **Input Scenario:** Execute defined test suite:
  1. Invert bit in CRC-17 / CRC-21 checksum.
  2. Insert 6 identical consecutive bits in data stream without dynamic stuff bit.
  3. Invert fixed stuff bit in CRC field.
  4. Reject an invalid logical DLC value ($>15$) before serialization; the physical DLC field is only four bits.
  5. Violate recessive ACK delimiter with dominant bit.
* **Expected Result:** Protocol validator rejects each corrupted frame and logs corresponding error code.
* **Pass Criteria:** $100\%$ detection rate across all defined corruption test cases.

### TST-007: False Positive Rate (FPR) Benchmark
* **Target Requirement:** REQ-07
* **Preconditions:** Train IDS classifier on chronological training split.
* **Input Scenario:** Evaluate classifier over 10,000 continuous benign CAN-FD frames.
* **Expected Result:** No false alarm cascades.
* **Pass Criteria:** $\text{FPR} = \frac{FP}{FP + TN} < 1.0\%$.

### TST-008: Processing Throughput and Latency
* **Target Requirement:** REQ-08
* **Preconditions:** Host system execution with timestamp benchmarking.
* **Input Scenario:** Benchmark feature extraction and classification over complete 10-second simulation dataset.
* **Expected Result:** Average frame processing time sub-100 $\mu$s; simulation throughput $> 10,000$ frames/sec.
* **Pass Criteria:** Throughput $\ge 10,000$ fps.

### TST-009: Determinism & Reproducibility Verification
* **Target Requirement:** REQ-09
* **Preconditions:** Two distinct simulation runs configured with identical random seed (42).
* **Input Scenario:** Compare frame-by-frame timestamps, bit streams, features, and model predictions.
* **Expected Result:** Hashes of output datasets and prediction logs match bit-for-bit.
* **Pass Criteria:** $100\%$ identity.

### TST-010: Python vs. Exported ANSI C Model Conformance
* **Target Requirement:** REQ-10
* **Preconditions:** Export trained decision tree to `models/exported/classifier.c`. Compile with GCC.
* **Input Scenario:** Run all feature vectors from validation test set through both Python `.predict()` and the compiled C executable.
* **Expected Result:** Every predicted class matches exactly.
* **Pass Criteria:** $\frac{N_{\text{identical\_predictions}}}{N_{\text{total\_samples}}} = 100.0\%$.
