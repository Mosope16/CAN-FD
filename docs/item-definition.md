# Item Definition: CAN-FD Intrusion Detection System (IDS)
**Standard Alignment:** ISO/SAE 21434:2021 (Road Vehicles — Cybersecurity Engineering), Clause 9

---

## 1. Item Purpose and Operational Context
The item under consideration is a **Software-Based CAN-FD Bit-Stream Intrusion Detection System (IDS)** with embedded-friendly Machine Learning attack classification.

Modern road vehicle electrical/electronic (E/E) architectures rely on Controller Area Network Flexible Data-Rate (CAN-FD) to transport safety-critical and high-throughput telemetry (powertrain, steering, braking, battery management). While CAN-FD expands payload capacity (up to 64 bytes) and data-phase bitrates (up to 2-5 Mbps), standard automotive bus topologies lack intrinsic message authentication, sender validation, and cryptographic encryption.

The item provides real-time detection, protocol diagnostics, and threat classification to mitigate malicious exploitation of automotive bus broadcast characteristics.

---

## 2. Item Boundaries and System Interfaces

```
                    +-------------------------------------------------------------+
                    |                       SYSTEM BOUNDARY                       |
                    |                                                             |
+---------------+   |  +--------------------+       +--------------------------+  |
| CAN-FD Bus    |====> |  CAN-FD Protocol   |=====> | Protocol Validator       |  |
| Physical/Bit  |   |  |  Bit-Stream Engine |       | (CRC, Stuffing, Framing) |===> Protocol Error Event
| Stream Stream |   |  +--------------------+       +--------------------------+  |
+---------------+   |            |                                |               |
                    |            v                                v               |
                    |  +--------------------+       +--------------------------+  |
                    |  | Logical CAN-FD     |=====> | Integer Feature Engine   |  |
                    |  | Frame Decoder      |       | (Rates, Deviations, Hist)|  |
                    |  +--------------------+       +--------------------------+  |
                    |                                             |               |
                    |                                             v               |
                    |                               +--------------------------+  |
                    |                               | Decision Tree Classifier |===> Behavioral Attack Alert
                    |                               | (Python / ANSI C Engine) |     (DoS, Fuzz, Spoof,
                    |                               +--------------------------+      Replay, Suppression)
                    +-------------------------------------------------------------+
```

### 2.1 In-Scope Components
1. **Bit-Stream Processing Unit:**
   - Logical frame serialization and deserialization conforming to ISO 11898-1:2015.
   - Dynamic bit-stuffing generator (rule of 5 consecutive identical bits) for arbitration and data phases.
   - ISO CAN-FD CRC-field generator: 3-bit Gray stuff counter, even parity bit, CRC-17 (payload $\le 16$ bytes) / CRC-21 (payload $> 16$ bytes), and fixed stuff bits inserted at deterministic 4-bit intervals.
   - Bit Rate Switch (BRS) dual-phase timing tracking.
2. **Protocol Validation Engine:**
   - Real-time bit-stream sanity verification.
   - Detection of bit-level corruption, CRC mismatches, stuff errors, fixed-stuff errors, DLC length inconsistencies, and frame formatting errors.
3. **Temporal & Behavioral Feature Engine:**
   - Integer-only feature extraction (zero floating-point latency on target ECUs).
   - Per-ID inter-arrival timing delta and expected-period deviation tracking.
   - Multi-scale sliding window aggregations (10ms, 50ms, 100ms, 500ms).
   - Payload byte change counts and historical sequence similarity comparison.
   - Missing-frame deadline supervisor for message suppression detection.
4. **Lightweight IDS Classifier:**
   - Supervised multi-class decision tree trained on synthetic vehicular workloads.
   - Fully deterministic integer logic exportable to embedded ANSI C (`classify(...)`).
5. **Deterministic Simulation & Ground-Truth Infrastructure:**
   - Reproducible simulation clockwork with tick-level granularity (microseconds).
   - Ground-truth event logging strictly decoupled from the IDS pipeline to prevent training data leakage.

### 2.2 Out-of-Scope Boundaries
1. **Analog Physical Transceiver Characteristics:** Analog differential bus voltage levels ($V_{diff}$), ringing, ground offsets, and termination impedance reflections are abstracted to logical bit streams.
2. **Hardware Security Module (HSM) Cryptography:** Hardware-enforced cryptographic SecOC CMAC validation is treated as a complementary layer; the item focuses on bit-stream protocol integrity and behavioral telemetry.

---

## 3. Operating Environment and Assumptions
1. **Bus Architecture:** CAN-FD bus configured at 500 kbps nominal arbitration rate and 2000 kbps (2 Mbps) data-phase bitrate.
2. **Deterministic Periodic Traffic:** Critical automotive control ECUs broadcast periodic frames with DBC-specified nominal intervals (e.g., 10ms for vehicle speed, 20ms for brake status).
3. **Execution Constraints:** The IDS target runtime is an automotive microprocessor or microcontroller with fixed-point arithmetic, strict memory ceilings, and real-time execution guarantees.
