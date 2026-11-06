# System Architecture & Technical Design Specification
**Standard Alignment:** ISO/SAE 21434:2021, Clause 10 (System Architecture Design)

---

## 1. Architectural Overview

The CAN-FD Intrusion Detection System is structured into decoupled, modular subsystems ensuring strict separation between traffic generation, ground-truth management, bit-stream encoding/decoding, protocol verification, integer feature extraction, and ML classification.

```mermaid
flowchart TD
    subgraph Traffic_And_Attacks ["Simulation & Traffic Generation Layer"]
        TG["CAN-FD Traffic Generator<br/>(DBC Message & Signal Models)"]
        AI["Attack Injection Engine<br/>(DoS, Fuzz, Spoof, Replay, Suppression)"]
        GTM["Ground-Truth Manager<br/>(Labels, Timestamps, Injected Metadata)"]
    end

    subgraph Protocol_Layer ["Bit-Stream & Protocol Engine"]
        FB["Frame Builder<br/>(CAN-FD Logical Frames)"]
        CE["CRC Engine<br/>(CRC-17 / CRC-21 + Stuff Count)"]
        BS["Bit Stuffer<br/>(Dynamic & ISO Fixed Stuffing)"]
        BC["Bit Corruptor<br/>(Physical Disturbance Modeling)"]
        FD["Frame Decoder<br/>(Bit-to-Frame Reconstruction)"]
        PV["Protocol Validator<br/>(CRC, Stuff, DLC, Form Verification)"]
    end

    subgraph Feature_Layer ["Monitoring & Feature Extraction Layer"]
        FM["Frame Monitor<br/>(Per-ID Timestamps, Counters)"]
        MMS["Missing Message Supervisor<br/>(Deadline Monitoring for Suppression)"]
        SW["Sliding Window Aggregator<br/>(10ms, 50ms, 100ms, 500ms Rates)"]
        FE["Integer Feature Engine<br/>(Fixed-Point Deviations & Delays)"]
    end

    subgraph Detection_Layer ["Detection & Classification Engine"]
        DT["Decision Tree Classifier<br/>(Python Scikit-Learn Inference)"]
        CEngine["Exported ANSI C Engine<br/>(Pure Integer Logic: classify())"]
        Alerts["IDS Event & Alert Dispatcher"]
    end

    subgraph Evaluation_Layer ["Verification & Evidence Engine"]
        Eval["Evaluation Engine<br/>(Confusion Matrix, Latency, Throughput)"]
        Trace["ISO 21434 Traceability Matrix"]
    end

    TG -->|Legitimate Frames| FB
    AI -->|Malicious Frames| FB
    AI -->|Suppression Directives| TG
    AI -->|Ground Truth Labels| GTM
    FB --> CE --> BS --> BC --> FD
    BC -.->|Bitstream Disturbance| PV
    FD --> PV
    FD --> FM
    FM --> MMS
    FM --> SW
    SW --> FE
    MMS --> FE
    FE -->|Integer Feature Vector| DT
    FE -->|Integer Feature Vector| CEngine
    PV -->|Protocol Corruption Alert (REQ-06)| Alerts
    DT -->|Behavioral Attack Alert (REQ-01..05)| Alerts
    CEngine -->|Target ECU Classification| Alerts
    Alerts --> Eval
    GTM -->|Validation Ground Truth Only| Eval
    Eval --> Trace
```

---

## 2. Subsystem Specifications

### 2.1 Traffic & Signal Generation (`src/generator`)
* **Message Definitions (`message_definitions.py`):** Configures message attributes according to DBC standards (ID, DLC, nominal cycle time, payload layout, signal scaling and endianness).
* **Signal Generator (`signal_generator.py`):** Generates realistic continuous and event signals (e.g., smoothly varying vehicle speed, engine coolant warming curve, fluctuating brake pedal input, steering angle oscillations) with realistic noise and physical boundaries.
* **Deterministic Engine (`traffic_generator.py`):** Uses an integer simulation clockwork (microseconds) and fixed random seeds to ensure reproducible simulation episodes across runs.

### 2.2 Attack Injection Engine (`src/attacks`)
* **Ground-Truth Decoupling:** The attack injector creates frames labeled with ground-truth metadata (e.g., `attack_type`, `attack_id`, `onset_timestamp`). These labels are routed solely to the `GroundTruthManager` and are strictly excluded from the feature extraction and classification pipeline to prevent data leakage.
* **Attack Modules:**
  1. `dos.py`: Transmits high-priority ID frames at microsecond intervals, saturating bus throughput.
  2. `fuzzing.py`: Generates pseudo-random IDs, randomized DLCs, and unstructured byte sequences.
  3. `spoofing.py`: Generates authentic-looking frames for existing IDs with conflicting sensor values and irregular transmission phases.
  4. `replay.py`: Captures genuine past message windows and retransmits them verbatim.
  5. `suppression.py`: Intercepts and silences specific periodic messages from the scheduled bus broadcast.

### 2.3 Bit-Stream & Protocol Engine (`src/protocol`)
* **Frame Builder (`frame_builder.py`):** Constructs standard CAN-FD frames including SOF (1 bit), Arbitration (11-bit standard ID or 29-bit extended), Control field (IDE, FDF, res, BRS, ESI, DLC), Data field (up to 64 bytes), CRC field, and ACK/EOF fields.
* **CRC Engine (`crc_engine.py`):** Implements ISO 11898-1:2015 polynomial arithmetic:
  - CRC-17 ($x^{17} + x^{16} + x^{14} + x^{13} + x^{11} + x^6 + x^4 + x^3 + x^1 + 1$) for payloads $\le 16$ bytes.
  - CRC-21 ($x^{21} + x^{20} + x^{13} + x^{11} + x^7 + x^4 + x^3 + 1$) for payloads $> 16$ bytes.
* **CRC Field Safeguards (`crc_field_encoder.py`):** Computes the 3-bit Gray-encoded Stuff Count + parity bit, and inserts fixed stuff bits every 4 bits in the CRC field starting with the inverse of the preceding bit.
* **Bit Stuffer (`bit_stuffer.py`):** Implements dynamic bit-stuffing rules (inserting inverse bit after 5 consecutive identical bits) across SOF, Arbitration, Control, and Data fields.
* **BRS Timing Model (`brs_timing.py`):** Models nominal bitrate (e.g., 500 kbps, 2 $\mu$s per bit) for arbitration/ACK/EOF and high-speed data bitrate (e.g., 2000 kbps, 0.5 $\mu$s per bit) when BRS is active.
* **Bit Corruptor (`bit_corruptor.py`):** Injects precise physical-layer bit corruptions for protocol-level verification.
* **Frame Decoder & Validator (`frame_decoder.py`, `validator.py`):** Reconstructs frames from bit streams and checks dynamic stuffing, CRC, fixed stuff bits, DLC boundary mappings, and frame formatting.

### 2.4 Feature Extraction & Monitoring (`src/features`, `src/monitor`)
* **Fixed-Point / Integer Constraints:** All features are integer-valued (microsecond time differences, rate counters, byte variation counts, similarity scales $0-1000$) to enable direct zero-overhead execution in microcontroller C without floating-point units.
* **Missing-Frame Supervisor:** Maintains an expected deadline schedule for all configured periodic IDs. If $(T_{\text{current}} - T_{\text{last\_seen}}) > \alpha \cdot T_{\text{expected}}$ (where $\alpha = 2.5$), a missing-frame deadline event is generated, allowing the detection of message suppression.
* **Feature Vector:**
  1. `frame_id`: 11-bit / 29-bit arbitration identifier
  2. `frame_dlc`: Encoded DLC (0-15)
  3. `payload_delta`: Absolute difference of first payload bytes from preceding frame of same ID
  4. `inter_arrival`: Microseconds elapsed since last frame of same ID
  5. `period_deviation`: Integer difference $(T_{\text{actual}} - T_{\text{expected}})$ in microseconds
  6. `id_rate`: Number of frames for this ID in active sliding window (50ms/100ms)
  7. `total_bus_rate`: Total frames across entire bus in active sliding window
  8. `id_seen_before`: Boolean flag (0 or 1) indicating if ID was present in configured DBC baseline
  9. `dlc_mismatch`: Boolean flag (0 or 1) indicating DLC discrepancy against baseline
  10. `payload_change_count`: Hamming distance / changed byte count relative to previous frame
  11. `protocol_error_count`: Number of protocol-level decoding faults detected in current window
  12. `missing_frame_count`: Count of expired frame deadlines detected in current window
  13. `replay_similarity`: Fixed-point similarity index ($0-1000$) with historical payload buffer
  14. `duplicate_count`: Exact duplicate payload count observed in sliding history

### 2.5 Decision Tree Classifier & C Exporter (`src/detection`)
* **Decision Tree Model:** Trained using scikit-learn with constrained depth (5 to 8) and balanced class weighting.
* **Classes:**
  - 0: Normal
  - 1: DoS
  - 2: Fuzzing
  - 3: Spoofing
  - 4: Replay
  - 5: Suppression
* **C-Code Generator (`export_c.py`):** Automatically traverses the trained tree graph and produces standalone ANSI C code:
  ```c
  int classify_frame(int frame_id, int frame_dlc, int payload_delta,
                     int inter_arrival, int period_deviation, int id_rate,
                     int total_bus_rate, int id_seen_before, int dlc_mismatch,
                     int payload_change_count, int protocol_error_count,
                     int missing_frame_count, int replay_similarity,
                     int duplicate_count);
  ```
* **C/Python Conformance:** Validated by compiling the generated C source with GCC into an executable test harness and comparing predictions against scikit-learn output on 100% of the test samples.
