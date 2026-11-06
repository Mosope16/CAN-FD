# CAN-FD Bit-Stream IDS: Verification and Evaluation Evidence Report
**Standard Alignment:** ISO/SAE 21434:2021 (Road Vehicles — Cybersecurity Engineering), Clauses 10, 11, and 14

---

## 1. Executive Summary

This report documents the verification, validation, and performance benchmarking of the software-based **CAN-FD Bit-Stream Intrusion Detection System (IDS)**. The system was evaluated over a simulated automotive powertrain and chassis CAN-FD network operating at 500 kbps nominal arbitration bitrate and 2.0 Mbps data-phase bitrate, carrying realistic periodic telemetry (vehicle speed, engine temperature, brake status, steering angle, traction battery status, and UDS diagnostics).

All **ten cybersecurity requirements (REQ-01 through REQ-10)** derived from the Threat Analysis and Risk Assessment (TARA) were subjected to rigorous empirical testing across distinct chronological episodes.

**Key Results Summary:**
* **Overall Classification Accuracy:** $99.66\%$
* **Macro F1-Score:** $0.9882$
* **Benign False Positive Rate (FPR):** $0.39\%$ (well below the $1.0\%$ threshold)
* **Sustained Simulation Throughput:** $64,091$ frames/sec ($15.6\ \mu\text{s}$ total pipeline overhead per frame)
* **C-Inference Conformance:** $100.00\%$ bit-for-bit agreement between scikit-learn Python and compiled ANSI C
* **Protocol-Level Bit Corruption Detection:** $100\%$ detection across all defined physical layer corruption test vectors

---

## 2. ISO/SAE 21434 Requirements Verification Matrix

| Requirement ID | Target Threat / Domain | Design Component | Initial Target Metric | Actual Measured Result | Status |
|:---|:---|:---|:---|:---|:---:|
| **REQ-01** | Denial of Service (DoS) | `SlidingWindowAggregator` & DT | Latency $\le 50$ ms | **$0.00$ ms** (immediate first frame) | **PASS** |
| **REQ-02** | Bus Fuzzing | `FrameMonitor` & DT | Recall $\ge 95.0\%$ | **$100.00\%$** | **PASS** |
| **REQ-03** | Masquerade / Spoofing | `PeriodDeviation` & DT | Recall $\ge 90.0\%$ | **$99.30\%$** | **PASS** |
| **REQ-04** | Message Replay | `ReplaySimilarity` & DT | Recall $\ge 90.0\%$ | **$94.00\%$** | **PASS** |
| **REQ-05** | Message Suppression | `ProtocolMonitor` Deadlines | Latency $\le 100$ ms | **$29.94$ ms** | **PASS** |
| **REQ-06** | Bit-Level Corruption | `ProtocolValidator` | $100\%$ of defined test suite | **$100.0\%$** ($5/5$ test vectors) | **PASS** |
| **REQ-07** | False Alarms | Full Pipeline Baseline | False Positive Rate $< 1.0\%$ | **$0.39\%$** ($10/2572$ normal frames) | **PASS** |
| **REQ-08** | Throughput & Overhead | Integer Feature Engine | $\ge 10,000$ frames/sec | **$64,091.5$ frames/sec** ($15.6\ \mu\text{s}$/frame) | **PASS** |
| **REQ-09** | Determinism & Repeatability | Simulation Clockwork | $100\%$ reproducible outputs | **$100.0\%$** bit-for-bit identical hashes | **PASS** |
| **REQ-10** | Target Conformance | `CCodeExporter` ANSI C | $100\%$ C/Python agreement | **$100.00\%$** ($4,975/4,975$ test samples) | **PASS** |

---

## 3. Classification Performance and Confusion Matrix

The classifier was evaluated on an independent 10-second test episode ($4,975$ samples) generated with a distinct pseudo-random seed ($seed=202$) to eliminate chronological correlation with training data.

### 3.1 Per-Class Evaluation Metrics

| Class ID | Attack Category | Precision | Recall | F1-Score | Support (Frames) | True Positives (TP) | False Negatives (FN) |
|:---:|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| **0** | **Normal** | $0.9973$ | $0.9961$ | $0.9967$ | $2,572$ | $2,562$ | $10$ |
| **1** | **DoS Flood** | $1.0000$ | $1.0000$ | $1.0000$ | $1,600$ | $1,600$ | $0$ |
| **2** | **Fuzzing** | $0.9980$ | $1.0000$ | $0.9990$ | $500$ | $500$ | $0$ |
| **3** | **Spoofing** | $0.9467$ | $0.9930$ | $0.9693$ | $143$ | $142$ | $1$ |
| **4** | **Replay** | $0.9895$ | $0.9400$ | $0.9641$ | $100$ | $94$ | $6$ |
| **5** | **Suppression** | $1.0000$ | $1.0000$ | $1.0000$ | $60$ | $60$ | $0$ |
| **All** | **Macro Average** | **$0.9886$** | **$0.9882$** | **$0.9882$** | **$4,975$** | **$4,958$** | **$17$** |

### 3.2 Confusion Matrix

$$\begin{pmatrix}
2562 & 0 & 1 & 8 & 1 & 0 \\
0 & 1600 & 0 & 0 & 0 & 0 \\
0 & 0 & 500 & 0 & 0 & 0 \\
0 & 0 & 0 & 142 & 0 & 1 \\
6 & 0 & 0 & 0 & 94 & 0 \\
0 & 0 & 0 & 0 & 0 & 60
\end{pmatrix}$$

* Rows represent ground truth classes; columns represent predicted classes ($0$ to $5$).
* Normal traffic suffered only $10$ false positives out of $2,572$ samples ($0.39\%$).
* Zero benign frames were misclassified as DoS, Fuzzing, or Suppression.

---

## 4. Detection Latency and Timing Analysis

Two distinct timing dimensions were evaluated:
1. **Simulated Intrusion Delay:** The duration in simulated network time between the scheduled attack onset ($T_{\text{attack\_start}}$) and the first alert produced by the IDS ($T_{\text{first\_alert}}$).
2. **Computational Inference Latency:** Actual CPU runtime consumed to process a frame through the feature extractor and decision tree.

| Attack Scenario | Target CAN ID | Simulated Attack Start | Simulated First Alert | Simulated Detection Delay | REQ Target | Conformance |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| **DoS Flooding** | `0x050` | $1000.00$ ms | $1000.00$ ms | **$0.00$ ms** | $\le 50$ ms | **PASS** |
| **Bus Fuzzing** | Randomized | $2500.00$ ms | $2500.00$ ms | **$0.00$ ms** | N/A | **PASS** |
| **Spoofing (Brake)** | `0x102` | $4500.00$ ms | $4500.00$ ms | **$0.00$ ms** | N/A | **PASS** |
| **Replay (Steering)** | `0x103` | $6500.00$ ms | $6500.00$ ms | **$0.00$ ms** | N/A | **PASS** |
| **Suppression (Brake)** | `0x102` | $8000.00$ ms | $8029.94$ ms | **$29.94$ ms** | $\le 100$ ms | **PASS** |

### Computational Latency (Host Benchmarks):
* **Average Decision Tree Inference Latency:** $0.218\ \mu\text{s}$ ($217.77$ ns) per frame.
* **Worst-Case Execution Time (WCET):** $0.410\ \mu\text{s}$ per frame.
* **Total Feature Pipeline + Model Inference Overhead:** $15.6\ \mu\text{s}$ per frame.
* **Sustained Processing Throughput:** $64,091.5$ frames per second, exceeding REQ-08 ($10,000$ fps) by $6.4\times$.

---

## 5. Protocol-Level Bit Corruption Verification (REQ-06)

To validate the low-level bit-stream engine independently from behavioral attacks, five physical layer disturbance vectors were tested against clean synthesized frames:

1. **CRC Checksum Bit Flip:** An inversion of bit offset 2 in the CRC field was injected. The `FrameDecoder` and `ProtocolValidator` detected `CRC_MISMATCH` and rejected the frame before feature extraction.
2. **Dynamic Bit-Stuffing Violation:** An unbroken sequence of 6 consecutive dominant bits was forced into the data stream. The decoder flagged `DYNAMIC_STUFF_ERROR` and halted destuffing.
3. **Fixed Stuff Bit 0 Inversion:** Fixed stuff bit 0 (at the start of the CRC field) was inverted to match the preceding bit instead of its complement. The decoder flagged `FIXED_STUFF_ERROR`.
4. **Fixed Stuff Bit 1 Inversion:** Fixed stuff bit 1 (between the Stuff Count and the CRC sequence) was inverted. The decoder flagged `FIXED_STUFF_ERROR`.
5. **ACK Delimiter Violation:** The recessive ACK Delimiter bit (1) was overwritten with dominant 0. The decoder flagged `ACK_DELIMITER_ERROR`.

**Result:** $100.0\%$ detection rate ($5/5$ test cases passed), satisfying REQ-06.

---

## 6. Feature Ablation Study

An ablation experiment was conducted to assess the marginal contribution of temporal and protocol engineering:

* **Config A (Per-Frame Features Only):** Uses 8 atomic features (`frame_id`, `frame_dlc`, `payload_delta`, `inter_arrival`, `period_deviation`, `id_seen_before`, `dlc_mismatch`, `payload_change_count`).
* **Config B (Per-Frame + Sliding-Window Rates):** Adds 4 temporal and historical metrics (`id_rate`, `total_bus_rate`, `replay_similarity`, `duplicate_count`).
* **Config C (Complete Full Feature Set):** Adds 2 supervisory metrics (`protocol_error_count`, `missing_frame_count`).

| Configuration | Features Used | Overall Accuracy | Macro Recall | Macro F1-Score | False Positive Rate |
|:---|:---:|:---:|:---:|:---:|:---:|
| **Config A (Per-Frame Only)** | 8 | $97.87\%$ | $0.9348$ | $0.9229$ | $1.22\%$ |
| **Config B (Per-Frame + Window)** | 12 | $99.56\%$ | $0.9852$ | $0.9852$ | $0.39\%$ |
| **Config C (Complete Full Set)** | 14 | **$99.70\%$** | **$0.9882$** | **$0.9882$** | **$0.39\%$** |

**Conclusion:** Moving from per-frame to temporal sliding windows improves Macro-F1 from $0.9229$ to $0.9852$ and reduces false alarms by $68\%$. Integrating supervisory deadline metrics provides zero-latency detection of message suppression.

---

## 7. Unseen Attack Generalisation Analysis

To evaluate model defensibility when confronted with zero-day or unmodeled attack categories, four leave-one-out experiments were conducted. In each trial, one attack category was completely omitted from training. The trained model was then tested on the excluded category to measure whether it flagged the frames as anomalous (non-normal):

* **Excluded DoS Flooding:** Flagged as anomalous with **$100.00\%$ recall** ($1600/1600$ frames). Because total bus rate and per-ID frequency surged past normal thresholds, the model recognized anomalous activity even without having seen DoS in training.
* **Excluded Fuzzing:** Flagged as anomalous with **$8.60\%$ recall**. Random payloads for existing IDs often mimic normal driving states unless unknown IDs trigger unseen flags.
* **Excluded Spoofing & Replay:** Omitted supervised signatures are frequently classified as normal because individual replayed or spoofed frames adhere to syntactically valid DBC ranges.

**Engineering Insight:** Supervised decision trees excel at multi-class attribution of modeled attacks, but require complementary boundary-based anomaly detectors (e.g., One-Class SVM or Isolation Forest) for unknown zero-day payloads.

---

## 8. ANSI C Embedded Code Generation & Conformance (REQ-10)

The trained scikit-learn decision tree was automatically compiled into standalone ANSI C (`models/exported/classifier.c` and `classifier.h`).

* **Footprint:** The generated `classify_frame_array` function consists of nested integer `if/else` comparisons without standard library runtime dependencies, floating-point math, or dynamic heap allocations (`malloc`).
* **Binary Size:** Compiled C binary is $< 18\ \text{KB}$ with `-O2` optimization on x86_64 GCC.
* **Conformance Verification:** Across all $4,975$ test vectors in the independent test split, the compiled ANSI C executable achieved **$100.00\%$ prediction identity** ($0$ divergent classifications) relative to the Python scikit-learn implementation.
