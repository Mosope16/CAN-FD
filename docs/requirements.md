# Cybersecurity Requirements Specification
**Standard Alignment:** ISO/SAE 21434:2021, Clause 10 & 11

---

## 1. Traceability Summary

The following requirements translate the Cybersecurity Goals established in the TARA into verifiable, measurable software and algorithmic specifications.

| Requirement ID | Associated Goal | Threat Scenario | Verification Method | Initial Target Metric |
|:---|:---|:---|:---|:---|
| **REQ-01** | CG-01 | T01 (DoS) | Automated Test / Latency Benchmark | Detection latency $\le 50$ ms |
| **REQ-02** | CG-02 | T02 (Fuzzing) | Confusion Matrix / ML Test | Recall $\ge 95\%$ |
| **REQ-03** | CG-03 | T03 (Spoofing) | Confusion Matrix / Timing Analysis | Recall $\ge 90\%$ |
| **REQ-04** | CG-04 | T04 (Replay) | Confusion Matrix / Similarity Metric | Recall $\ge 90\%$ |
| **REQ-05** | CG-05 | T05 (Suppression) | Deadline Monitor Test | Detection latency $\le 100$ ms |
| **REQ-06** | CG-06 | T06 (Bit Corruption) | Protocol Suite Unit Tests | $100\%$ detection of defined test cases |
| **REQ-07** | CG-01-05 | All | Benign Evaluation Benchmark | False Positive Rate (FPR) $< 1.0\%$ |
| **REQ-08** | Non-Functional | All | Throughput Benchmark | Process $\ge 10,000$ frames/sec (software simulation) |
| **REQ-09** | Architecture | All | Deterministic Regression Test | $100\%$ reproducible outputs with identical seed |
| **REQ-10** | Architecture | All | C/Python Conformance Test | $100\%$ inference agreement across all test samples |

---

## 2. Detailed Requirements

### REQ-01: Denial of Service Detection Latency
* **Requirement:** The IDS shall flag a bus flooding attack within 50 ms of attack onset in simulated time.
* **Rationale:** Automotive CAN-FD bus saturation rapidly starves critical control loops. Alerting within 50 ms allows gateway ECUs to implement bus-off isolation or switch to safe default states.
* **Success Criteria:** $T_{\text{first\_alert}} - T_{\text{attack\_start}} \le 50.0 \text{ ms}$.

### REQ-02: Fuzzing Attack Classification Recall
* **Requirement:** The IDS shall classify injected randomized frames with a recall rate of at least 95%.
* **Rationale:** Fuzzing involves unknown identifiers, malformed payload signatures, or unconfigured DLCs that must not go unnoticed.
* **Success Criteria:** $\frac{TP_{\text{fuzz}}}{TP_{\text{fuzz}} + FN_{\text{fuzz}}} \ge 0.95$.

### REQ-03: Spoofing Attack Classification Recall
* **Requirement:** The IDS shall detect unauthorized transmission of legitimate CAN IDs with a recall rate of at least 90%.
* **Rationale:** Attackers spoofing existing sensor IDs distort actuation commands. Temporal deviation and payload gradient features must identify the spoofed frames.
* **Success Criteria:** $\frac{TP_{\text{spoof}}}{TP_{\text{spoof}} + FN_{\text{spoof}}} \ge 0.90$.

### REQ-04: Replay Attack Classification Recall
* **Requirement:** The IDS shall detect retransmitted historical message sequences with a recall rate of at least 90%.
* **Rationale:** Stale telemetry undermines closed-loop stability. Duplicate payload tracking and inter-arrival regularity identify replayed traffic.
* **Success Criteria:** $\frac{TP_{\text{replay}}}{TP_{\text{replay}} + FN_{\text{replay}}} \ge 0.90$.

### REQ-05: Message Suppression Detection
* **Requirement:** The IDS shall detect the non-arrival of an expected periodic CAN-FD frame within 100 ms of its expected arrival deadline.
* **Rationale:** Silent loss of steering or brake telemetry requires prompt diagnostic alert.
* **Success Criteria:** $T_{\text{suppression\_alert}} - T_{\text{expected\_deadline}} \le 100.0 \text{ ms}$.

### REQ-06: Protocol-Level Bit Corruption Detection
* **Requirement:** The protocol validator shall identify 100% of defined corruption test cases (CRC bit flips, stuff bit violations, fixed stuff bit errors, invalid DLC representations, and ACK delimiter corruptions).
* **Rationale:** Low-level physical bit corruptions must be distinguished from syntactically valid malicious payloads.
* **Success Criteria:** Detected corruptions in test suite $= \text{Total defined corruptions } (100\%)$.

### REQ-07: False Positive Rate (FPR) Control
* **Requirement:** On pure benign CAN-FD traffic, the IDS shall maintain a False Positive Rate of less than 1.0%.
* **Rationale:** High false alarm rates cause alert fatigue and unnecessary diagnostic fail-safes.
* **Success Criteria:** $\frac{FP}{FP + TN} < 0.010$.

### REQ-08: Execution Throughput & Computational Efficiency
* **Requirement:** The IDS feature extractor and classifier shall sustain a minimum simulation throughput of 10,000 frames per second on standard workstation CPUs, with sub-microsecond decision tree inference per frame.
* **Rationale:** Automotive microcontrollers have constrained clock speeds.

### REQ-09: Simulation Determinism and Reproducibility
* **Requirement:** Given identical configuration files and random seeds, the simulation, attack injection, feature extraction, and classification shall yield bit-for-bit identical results.
* **Rationale:** Required for ISO/SAE 21434 verification evidence reproducibility.

### REQ-10: C-Inference Equivalence
* **Requirement:** The exported ANSI C decision tree classifier shall achieve 100% classification agreement with the Python scikit-learn model over all evaluated test vectors.
* **Rationale:** Guarantees zero discrepancy between workstation training and target ECU deployment.
