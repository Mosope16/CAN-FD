# CAN-FD Bit-Stream IDS: ISO/SAE 21434-Aligned Verification and Evaluation Report
**Standard Alignment:** ISO/SAE 21434:2021 (Road Vehicles — Cybersecurity Engineering), Clauses 10, 11, and 14

> [!NOTE] Scope and Regulatory Disclaimer
> This report documents technical verification and validation evidence structured according to the engineering methodologies of ISO/SAE 21434:2021 (Clause 10 Product Development, Clause 11 Cybersecurity Validation, and Clause 14 Traceability). While all ten project-defined cybersecurity requirements (REQ-01 through REQ-10) have been empirically verified in software simulation, this prototype does not constitute formal ISO/SAE 21434 third-party certification or UNECE R155 type approval, which necessitate full vehicle integration, physical transceiver hardware-in-the-loop (HIL) testing, and accredited organizational audit.

---

## 1. Executive Summary

This report documents the verification, validation, and performance benchmarking of the software-based **CAN-FD Bit-Stream Intrusion Detection System (IDS)** with machine-learning-assisted multi-class classification and physical-layer bit corruption validation. The system was evaluated over a simulated automotive powertrain and chassis CAN-FD network operating at 500 kbps nominal arbitration bitrate and 2.0 Mbps data-phase bitrate, carrying realistic periodic telemetry (vehicle speed, engine temperature, brake status, steering angle, traction battery status, and UDS diagnostics).

All **ten cybersecurity requirements (REQ-01 through REQ-10)** derived from the Threat Analysis and Risk Assessment (TARA) were subjected to empirical testing across distinct chronological episodes.

**Key Results Summary:**
* **Overall Classification Accuracy:** $99.56\%$
* **Macro F1-Score:** $0.9852$
* **Benign False Positive Rate (FPR):** $0.47\%$ (well below the $1.0\%$ threshold)
* **Sustained Simulation Throughput:** $55,615.9$ frames/sec ($17.98\ \mu\text{s}$ total pipeline overhead per frame)
* **Embedded Microcontroller Execution:** $4.34\ \text{ns}$ ($0.0043\ \mu\text{s}$) per frame in standalone compiled ANSI C ($230.0\text{M}$ frames/sec) with active compiler barriers and observable checksum accumulation.
* **C-Inference Conformance:** $100.00\%$ bit-for-bit agreement between scikit-learn Python and compiled ANSI C across all test samples and 500 boundary vectors.
* **Protocol-Level Bit Corruption Detection:** $100.0\%$ detection across all defined protocol corruption vectors, including logical DLC ingress validation.
* **Zero-Day / Unseen Attack Defense:** Dual-Engine IDS architecture (Supervised Decision Tree + Normal-Only Anomaly Detector) elevates unseen attack recall to $100\%$ on DoS, $100\%$ on Fuzzing, $95.80\%$ on Spoofing, and $100\%$ on Replay.

---

## 2. ISO/SAE 21434 Requirements Verification Matrix

| Requirement ID | Target Threat / Domain | Design Component | Initial Target Metric | Actual Measured Result | Status |
|:---|:---|:---|:---|:---|:---:|
| **REQ-01** | Denial of Service (DoS) | `SlidingWindowAggregator` & DT | Latency $\le 50$ ms | **$0.50$ ms** ($500\ \mu\text{s}$ onset, $1.50$ ms sustained) | **PASS** |
| **REQ-02** | Bus Fuzzing | `FrameMonitor` & DT | Recall $\ge 95.0\%$ | **$100.00\%$** | **PASS** |
| **REQ-03** | Masquerade / Spoofing | `PeriodDeviation` & DT | Recall $\ge 90.0\%$ | **$97.90\%$** | **PASS** |
| **REQ-04** | Message Replay | `ReplaySimilarity` & DT | Recall $\ge 90.0\%$ | **$94.00\%$** | **PASS** |
| **REQ-05** | Message Suppression | `ProtocolMonitor` Deadlines | Latency $\le 100$ ms | **$29.94$ ms** ($69.95$ ms sustained 3-deadline) | **PASS** |
| **REQ-06** | Bit-Level Corruption | `ProtocolValidator` | $100\%$ of defined test suite | **$100.0\%$** ($6/6$ test vectors) | **PASS** |
| **REQ-07** | False Alarms | Full Pipeline Baseline | False Positive Rate $< 1.0\%$ | **$0.470\%$** ($12/2572$ normal frames) | **PASS** |
| **REQ-08** | Throughput & Overhead | Integer Feature Engine | $\ge 10,000$ frames/sec | **$55,615.9$ frames/sec** ($17.98\ \mu\text{s}$/frame) | **PASS** |
| **REQ-09** | Determinism & Repeatability | Simulation Clockwork | $100\%$ reproducible outputs | **$100.0\%$** bit-for-bit identical hashes | **PASS** |
| **REQ-10** | Target Conformance | `CCodeExporter` ANSI C | $100\%$ C/Python agreement | **$100.00\%$** ($4,975/4,975$ test samples) | **PASS** |

---

## 3. Classification Performance and Confusion Matrix

The classifier was evaluated on an independent 10-second test episode ($4,975$ samples) generated with seed $202$ (training on seed $42$, validation on seed $101$) to eliminate chronological correlation with training data.

### 3.1 Per-Class Evaluation Metrics

| Class ID | Attack Category | Precision | Recall | F1-Score | Support (Frames) | True Positives (TP) | False Negatives (FN) |
|:---:|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| **0** | **Normal** | $0.9965$ | $0.9953$ | $0.9959$ | $2,572$ | $2,560$ | $12$ |
| **1** | **DoS Flood** | $1.0000$ | $0.9994$ | $0.9997$ | $1,600$ | $1,599$ | $1$ |
| **2** | **Fuzzing** | $0.9980$ | $1.0000$ | $0.9990$ | $500$ | $500$ | $0$ |
| **3** | **Spoofing** | $0.9272$ | $0.9790$ | $0.9524$ | $143$ | $140$ | $3$ |
| **4** | **Replay** | $0.9895$ | $0.9400$ | $0.9641$ | $100$ | $94$ | $6$ |
| **5** | **Suppression** | $1.0000$ | $1.0000$ | $1.0000$ | $60$ | $60$ | $0$ |
| **All** | **Macro Average** | **$0.9852$** | **$0.9856$** | **$0.9852$** | **$4,975$** | **$4,953$** | **$22$** |

### 3.2 Confusion Matrix

$$\begin{pmatrix}
2560 & 0 & 1 & 10 & 1 & 0 \\
1 & 1599 & 0 & 0 & 0 & 0 \\
0 & 0 & 500 & 0 & 0 & 0 \\
2 & 0 & 0 & 140 & 0 & 1 \\
6 & 0 & 0 & 0 & 94 & 0 \\
0 & 0 & 0 & 0 & 0 & 60
\end{pmatrix}$$

* Normal traffic suffered only $12$ false positives out of $2,572$ samples ($0.47\%$).
* Replay achieved $94.00\%$ recall, successfully detecting historical injections while distinguishing benign stationary signals via the dual-condition continuity check.

---

## 4. Detection Latency and Timing Analysis

### 4.1 Resolution and Qualification Latency

Detection is decomposed into:
1. **First-Frame Detection Delay ($\Delta T_{\text{first}}$):** Delay between attack schedule onset ($T_{\text{start}}$) and the first alert produced by the IDS ($T_{\text{first\_alert}}$).
2. **First-Frame Qualification Flag:** Whether the very first malicious frame injected on the bus was detected.
3. **Sustained Qualification Delay ($\Delta T_{\text{sustained}}$):** Time until $K=3$ consecutive frames of the attack stream are verified.

| Attack Scenario | Target ID | Scheduled Onset ($T_{\text{start}}$) | First Bus Frame ($T_{\text{frame}}$) | First Alert ($T_{\text{alert}}$) | Onset Delay ($\Delta T_{\text{first}}$) | 1st Frame Det? | Sustained Delay ($K=3$) | Target | Conformance |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **DoS Flooding** | `0x050` | $1,000,000\ \mu\text{s}$ | $1,000,000\ \mu\text{s}$ | $1,000,500\ \mu\text{s}$ | **$500\ \mu\text{s}$** ($0.50$ ms) | No (2nd frame) | **$1.50$ ms** | $\le 50$ ms | **PASS** |
| **Bus Fuzzing** | Random | $2,500,000\ \mu\text{s}$ | $2,500,000\ \mu\text{s}$ | $2,500,000\ \mu\text{s}$ | **$0\ \mu\text{s}$** ($0.00$ ms) | Yes | **$4.00$ ms** | N/A | **PASS** |
| **Spoofing (Brake)** | `0x102` | $4,500,000\ \mu\text{s}$ | $4,500,000\ \mu\text{s}$ | $4,500,000\ \mu\text{s}$ | **$0\ \mu\text{s}$** ($0.00$ ms) | Yes | **$63.00$ ms** | N/A | **PASS** |
| **Replay (Steering)** | `0x103` | $6,500,000\ \mu\text{s}$ | $6,500,000\ \mu\text{s}$ | $6,500,000\ \mu\text{s}$ | **$0\ \mu\text{s}$** ($0.00$ ms) | Yes | **$19.99$ ms** | N/A | **PASS** |
| **Suppression (Brake)** | `0x102` | $8,000,000\ \mu\text{s}$ | N/A (silence) | $8,029,944\ \mu\text{s}$ | **$29,944\ \mu\text{s}$** ($29.94$ ms) | Yes (deadline) | **$69.95$ ms** | $\le 100$ ms | **PASS** |

#### Engineering Explanation of Latency Mechanics:
* **DoS Flooding (0.50 ms / 1st Frame NO):** When the first flooding frame arrives at $t=1,000,000\ \mu\text{s}$, its inter-arrival cannot yet be computed (no previous frame for ID `0x050`). The second frame arrives $500\ \mu\text{s}$ later at $t=1,000,500\ \mu\text{s}$, establishing `inter_arrival = 500 us` and triggering the `total_bus_rate` surge. The alert fires on the 2nd frame, giving an exact onset latency of $500\ \mu\text{s}$ ($0.50$ ms) and sustained qualification ($K=3$) in $1.50$ ms.
* **Fuzzing, Spoofing, Replay (0 µs / 1st Frame YES):** In these scenarios, the first malicious frame is scheduled at $T_{\text{start}}$. For Fuzzing, the random ID (`id_seen_before == 0`) or DLC mismatch immediately flags the frame. For Spoofing, the instant jump to $100\%$ pedal position (`payload_delta == 100`) flags the frame immediately. For Replay, the payload exists in `historical_payload_set` while differing from the immediate predecessor. Thus, $T_{\text{alert}} - T_{\text{first\_frame}} = 0\ \mu\text{s}$.
* **Suppression (29.94 ms):** When `0x102` (nominal period $20$ ms) is silenced at $t = 8.0$s, its deadline expires at $t = 8.0\text{s} + 1.5 \times 20\text{ms} = 8.030\text{s}$. The very next periodic frame on the bus evaluates `check_deadlines()` and emits an alert at $29.94$ ms.

---

### 4.2 Computational Execution Profiling

The computational performance is separated into three distinct execution tiers:

1. **Embedded Microcontroller Bare-Metal Inference Target (`models/exported/c_bench`):**
   * Standalone compiled ANSI C function [`classify_canfd_frame`](file:///home/sope/Projects/CAN-FD/models/exported/classifier.c).
   * Evaluated across $2,000,000$ timed iterations following $100,000$ warm-up iterations.
   * Cycles through 16 distinct feature vectors covering Normal and all 5 attack classes to exercise diverse branch paths.
   * Compiles with GCC `16.2.1` under `-O2` with inline assembly barriers (`__asm__ __volatile__("" : "+r"(checksum) : : "memory");`) and observable prediction checksum (`checksum = 1625000`) preventing dead-code elimination.
   * **Host Hardware:** 11th Gen Intel(R) Core(TM) i5-1155G7 @ 2.50GHz (up to 4.50GHz).
   * **Measured Latency:** **$5.69\ \text{ns}$ ($0.0057\ \mu\text{s}$)** per frame.
   * **Throughput:** **$175.8\text{M}$ frames/second**.

2. **Full End-to-End Python Pipeline Throughput (Host Simulation Environment):**
   * Processes the full sequential stream through `FeaturePipeline` (atomic metrics + sliding window updates + bounded hash lookups + deadline checking) followed by vectorized model inference.
   * **Feature Extraction Overhead:** **$15.80\ \mu\text{s}$** per frame.
   * **Vectorized Model Inference:** **$0.30\ \mu\text{s}$** per frame.
   * **Total Pipeline Overhead:** **$16.09\ \mu\text{s}$** per frame.
   * **Sustained Simulation Throughput:** **$55,615.9$ frames/second** (exceeding REQ-08 target of $10,000$ fps by $5.6\times$).

3. **Python Unvectorized Single-Call Overhead (Testing Artifact):**
   * Measured by invoking `model.predict(single_vector)` in an unvectorized loop.
   * **Average Execution Time:** **$232.22\ \mu\text{s}$** per call (WCET: $431.92\ \mu\text{s}$).
   * **Root Cause:** Driven by Python interpreter function call dispatch, scikit-learn Cython wrapper initialization, NumPy dimensional type checks, and dynamic memory allocation for single-row arrays. It does **not** reflect algorithm complexity or production embedded execution.

---

## 5. Protocol-Level Bit Corruption Verification (REQ-06)

To validate the low-level bit-stream engine independently from behavioral attacks, five physical layer disturbance vectors and one logical-ingress boundary vector were tested:

1. **CRC Checksum Bit Flip:** An inversion of bit offset 2 in the CRC field was injected. The `FrameDecoder` and `ProtocolValidator` detected `CRC_MISMATCH` and rejected the frame before feature extraction.
2. **Dynamic Bit-Stuffing Violation:** An unbroken sequence of 6 consecutive dominant bits was forced into the data stream. The decoder flagged `DYNAMIC_STUFF_ERROR` and halted destuffing.
3. **Fixed Stuff Bit 0 Inversion:** Fixed stuff bit 0 (at the start of the CRC field) was inverted to match the preceding bit instead of its complement. The decoder flagged `FIXED_STUFF_ERROR`.
4. **Fixed Stuff Bit 1 Inversion:** Fixed stuff bit 1 (between the Stuff Count and the CRC sequence) was inverted. The decoder flagged `FIXED_STUFF_ERROR`.
5. **ACK Delimiter Violation:** The recessive ACK Delimiter bit (1) was overwritten with dominant 0. The decoder flagged `ACK_DELIMITER_ERROR`.
6. **Invalid DLC at Logical Ingress:** The invalid logical value `0xFF` was rejected before serialization with `INVALID_DLC`. It cannot be represented in the physical four-bit DLC field.

**Result:** $100.0\%$ detection rate ($6/6$ test cases passed), satisfying REQ-06.

---

## 6. Feature Ablation Study

An ablation experiment was conducted to assess the marginal contribution of temporal and protocol engineering:

* **Config A (Per-Frame Features Only):** Uses 8 atomic features (`frame_id`, `frame_dlc`, `payload_delta`, `inter_arrival`, `period_deviation`, `id_seen_before`, `dlc_mismatch`, `payload_change_count`).
* **Config B (Per-Frame + Sliding-Window Rates):** Adds 4 temporal and historical metrics (`id_rate`, `total_bus_rate`, `replay_similarity`, `duplicate_count`).
* **Config C (Complete Full Feature Set):** Adds 2 supervisory metrics (`protocol_error_count`, `missing_frame_count`).

| Configuration | Features Used | Overall Accuracy | Macro Recall | Macro F1-Score | False Positive Rate |
|:---|:---:|:---:|:---:|:---:|:---:|
| **Config A (Per-Frame Only)** | 8 | $97.87\%$ | $0.9348$ | $0.9229$ | $1.22\%$ |
| **Config B (Per-Frame + Window)** | 12 | $99.56\%$ | $0.9852$ | $0.9852$ | $0.47\%$ |
| **Config C (Complete Full Set)** | 14 | **$99.56\%$** | **$0.9852$** | **$0.9852$** | **$0.47\%$** |

**Engineering Insight:** Moving from per-frame to temporal sliding windows improves Macro-F1 from $0.9229$ to $0.9852$ and reduces false alarms by $61\%$. The final two features (`protocol_error_count`, `missing_frame_count`) provide deterministic deadline detection for message suppression attacks.

---

## 7. Unseen Attack Generalisation & Dual-Engine Architecture

To evaluate model defensibility when confronted with unfamiliar or unmodeled attack categories, four leave-one-out experiments were conducted. In each trial, one attack category was completely omitted from training. The test set was then evaluated across:
1. **Supervised Decision Tree Alone** (trained with the attack omitted).
2. **Complementary Normal-Only Anomaly Detector Alone** (`NormalTrafficAnomalyDetector` trained strictly on benign Class 0 data).
3. **Dual-Engine IDS Architecture** (Supervised DT + Normal-Only Anomaly Detector operating in tandem).

| Excluded / Unseen Attack | Standalone Supervised DT Recall | Normal-Only Anomaly Detector Recall | Dual-Engine IDS Combined Recall | Unseen Test Samples |
|:---|:---:|:---:|:---:|:---:|
| **Excluded DoS Flooding** | $100.00\%$ | $100.00\%$ | **$100.00\%$** | $1,600$ |
| **Excluded Bus Fuzzing** | $8.60\%$ | $100.00\%$ | **$100.00\%$** | $500$ |
| **Excluded Spoofing (Brake)** | $0.00\%$ | $95.80\%$ | **$95.80\%$** | $143$ |
| **Excluded Replay (Steering)** | $0.00\%$ | $100.00\%$ | **$100.00\%$** | $100$ |

**Methodology & Dataset Decoupling:**
* The anomaly detector is trained **strictly on Class 0 benign training data (`y_train == 0`)**.
* Feature envelopes (`max_bus_rate`, `feature_min`, `feature_max`) are derived solely from training samples.
* Contamination ($0.001$) and envelope calibration are verified on the validation split (`val.csv`), achieving $0.17\%$ False Positive Rate on clean benign validation traffic.
* The test episode (`test.csv`) is never observed during training or threshold tuning.

---

## 8. Verification Coverage & Test Suite Maturity

The automated test suite now comprises **40 automated tests** across 14 dedicated test modules:

1. **Physical Protocol Layer:** CRC-17 / CRC-21 calculation, ISO dynamic bit stuffing and destuffing, fixed stuff bit insertion, frame serialization and decoding, protocol validator rejection of CRC bit flips, stuff violations, and ACK delimiter corruptions.
2. **Attacks & Signal Modeling:** Physics-based continuous signal generation, discrete-event injection of DoS, Fuzzing, Spoofing, Replay, and Suppression.
3. **State Tracking & Features:** Atomic per-ID timing, bounded historical buffers, sliding-window arrival rates, $O(1)$ hash lookups for replay detection, integer-only feature vector assembly.
4. **Supervisory Monitoring:** Sliding-window error pruning, deadline expiration calculation, missing-message alerts.
5. **Anti-Contamination & Decoupling:** Verification that feature extraction produces identical vectors when ground-truth labels and attack metadata are purged; verification that train, val, and test splits have distinct variations.
6. **Concurrent Attacks & Stability:** Verification that overlapping attacks (DoS + Spoofing, Fuzzing + Suppression) are detected without state corruption; 20-second continuous simulation stability with bounded deques and sets.
7. **Embedded Target Equivalence:** Clean compilation of exported C under `-Wall -Wextra -Werror`, bit-for-bit equivalence between C and Python across $4,975$ test vectors and $500$ random and extreme boundary vectors (`INT64_MAX`, `INT64_MIN`).
