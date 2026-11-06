# Threat Analysis and Risk Assessment (TARA)
**Standard Alignment:** ISO/SAE 21434:2021, Clause 15

---

## 1. Asset Identification and Security Objectives

| Asset ID | Asset Name | Description | Cybersecurity Property | Impact Category |
|:---|:---|:---|:---|:---|
| **AST-01** | CAN-FD Communication Bus | Arbitration and physical transmission medium | Availability, Integrity | Safety, Operational |
| **AST-02** | Powertrain & Chassis Control Frames | Messages governing vehicle speed, braking, steering | Authenticity, Integrity, Freshness | Safety |
| **AST-03** | Diagnostic and Battery Telemetry | State of charge, thermal sensor readings, UDS diagnostics | Integrity, Availability | Operational, Safety |
| **AST-04** | IDS Monitoring Engine | Real-time intrusion detection pipeline and classifier state | Integrity, Availability, Reliability | Operational |

---

## 2. Threat Scenarios

### T01: Denial of Service (Bus Flooding)
* **Description:** An adversary with access to the CAN-FD bus transmits high-priority dominant identifier frames (e.g., ID `0x000`-`0x050`) at extreme rates (e.g., every 500 $\mu$s).
* **Vulnerability:** Standard CAN-FD CSMA/CR arbitration always prioritizes lower numeric IDs.
* **Impact:** Safety-critical ECUs (brakes, steering) are starved of bus access, preventing safety state updates.
* **Impact Rating:** Safety: Severe (Catastrophic); Operational: High.
* **Risk Value:** High.

### T02: Bus Fuzzing (Randomized Injection)
* **Description:** An attacker transmits semi-randomized frames with arbitrary CAN IDs, invalid/valid DLCs, and random payloads.
* **Vulnerability:** Automotive ECUs lack defensive payload sanitation against unexpected signals.
* **Impact:** Receiver buffers overflow; unhandled firmware exceptions force ECUs into fallback limp modes or system resets.
* **Impact Rating:** Safety: Major; Operational: High.
* **Risk Value:** High.

### T03: Masquerade / Spoofing
* **Description:** An attacker transmits forged messages mimicking legitimate ECUs (e.g., ID `0x102` BrakeStatus) carrying hazardous payload values (e.g., reporting 0% brake pressure during emergency stop).
* **Vulnerability:** Broadcast CAN-FD frames lack sender authentication signatures.
* **Impact:** Downstream actuators execute dangerous control actions based on falsified sensor readings.
* **Impact Rating:** Safety: Severe; Operational: Critical.
* **Risk Value:** Very High.

### T04: Message Replay Attack
* **Description:** An attacker snoops legitimate traffic on the CAN-FD bus during normal vehicle operation, records the frame payloads, and replays them verbatim later.
* **Vulnerability:** Lack of message freshness checks (monotonically incrementing counters or timestamps).
* **Impact:** Overwrites current sensor state with stale operational data, deceiving safety algorithms.
* **Impact Rating:** Safety: Major; Operational: Moderate.
* **Risk Value:** Medium-High.

### T05: Message Suppression
* **Description:** An adversary forces an ECU into bus-off state (via dominant pulse collision or wire tampering) or blocks transmission of periodic control messages (e.g., ID `0x101` EngineTemp).
* **Vulnerability:** Silent failures may not immediately trigger DTCs before thermal or mechanical damage occurs.
* **Impact:** Supervisory ECUs operate blind to critical sensor states, causing catastrophic mechanical failure.
* **Impact Rating:** Safety: Major; Operational: High.
* **Risk Value:** High.

### T06: Bit-Level Protocol Corruption
* **Description:** Electromagnetic interference, fault injection, or deliberate transceiver timing corruption induces bit inversions, stuff-bit errors, CRC mismatches, or malformed frame delimiters.
* **Vulnerability:** Physical layer bit disturbances disrupt frame parsing in hardware CAN controllers.
* **Impact:** Corruption causes frame drops, error frame cascades, and potential bus-off conditions.
* **Impact Rating:** Safety: Moderate; Operational: Moderate.
* **Risk Value:** Medium.

---

## 3. Cybersecurity Goals (CG)

* **CG-01 (Availability Defense):** The system shall detect high-priority bus flooding (DoS) rapidly to enable bus management or fallback control.
* **CG-02 (Robustness against Fuzzing):** The system shall identify anomalous IDs and unstructured payloads with high recall.
* **CG-03 (Authenticity & Integrity Defense):** The system shall detect forged messages masquerading as legitimate ECUs by observing timing jitter and signal variation anomalies.
* **CG-04 (Freshness Assurance):** The system shall detect replayed message sequences through historical duplicate and similarity tracking.
* **CG-05 (Supervisory Availability):** The system shall track expected periodic deadlines and alert upon message suppression.
* **CG-06 (Protocol Integrity):** The system shall validate low-level bit stream structures and flag malformed, CRC-corrupted, or stuff-violated frames.
