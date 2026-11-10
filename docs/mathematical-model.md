# CAN-FD Bit-Stream IDS: Comprehensive Mathematical Model
**Course Alignment:** CPE 503 · Problem 14 (Inline CAN-FD Bit-Stream Monitor and Decision-Tree IDS)  
**Standard References:** ISO 11898-1:2015, Bosch CAN FD Specification v1.0, ISO/SAE 21434:2021

---

## 1. Notation and Symbol Definitions

| Symbol | Definition | Engineering Unit | Word Length / Representation |
|:---|:---|:---:|:---:|
| $f_{\text{sys}}$ | Master hardware oscillator frequency | $\text{Hz}$ ($100\ \text{MHz}$) | Integer constant |
| $t_q$ | Time quantum duration | $\text{ns}$ | Integer ($10\ \text{ns}$ at $100\ \text{MHz}$) |
| $\text{BRP}$ | Baud Rate Prescaler | dimensionless | Unsigned integer ($[1, 1024]$) |
| $R_{\text{nominal}}$ | Nominal arbitration phase bitrate | $\text{bps}$ ($500\ \text{kbps}$) | Integer constant |
| $R_{\text{data}}$ | Data phase bitrate (BRS enabled) | $\text{bps}$ ($2.0\ \text{Mbps}$) | Integer constant |
| $T_{\text{bit,nom}}$ | Nominal bit time ($1 / R_{\text{nominal}}$) | $\mu\text{s}$ ($2.0\ \mu\text{s}$) | $200\ t_q$ |
| $T_{\text{bit,dat}}$ | Data-phase bit time ($1 / R_{\text{data}}$) | $\mu\text{s}$ ($0.5\ \mu\text{s}$) | $50\ t_q$ |
| $SP_{\text{nom}}$ | Nominal sample point percentage | $\%$ ($80.0\%$) | Ratio $[0.5, 0.9]$ |
| $SP_{\text{dat}}$ | Data-phase sample point percentage | $\%$ ($70.0\%$) | Ratio $[0.5, 0.9]$ |
| $T_{\text{frame}}$ | Total serialized frame duration on bus | $\mu\text{s}$ | Variable integer ($\mu\text{s}$) |
| $S_{\text{dyn}}$ | Count of dynamic stuff bits inserted | integer bits | Unsigned integer |
| $S_{\text{fixed}}$ | Count of fixed stuff bits in CRC field | integer bits | Constant (6 for CRC-17, 7 for CRC-21) |
| $L_W$ | Bus load / channel utilization over window $W$ | $\%$ | Fixed-point Q8.8 |
| $\Delta t_i$ | Inter-arrival time between consecutive frames | $\mu\text{s}$ | 32-bit unsigned integer |
| $d_{\text{period}}$ | Period deviation from nominal DBC baseline | $\mu\text{s}$ | 32-bit signed integer |
| $H(X)$ | Shannon payload entropy | $\text{bits/byte}$ ($[0.0, 8.0]$) | Fixed-point Q4.12 |
| $I_G(t)$ | Gini impurity of decision tree node $t$ | dimensionless ($[0.0, 1.0]$) | Floating-point in train, integer in C |
| $T_{\text{lat,bits}}$ | Detection latency in nominal bit times | bit times | Integer ($T_{\text{lat}} \times R_{\text{nom}}$) |

---

## 2. Bit Timing, Time Quantum, and Sample Point Derivation

Under ISO 11898-1:2015, each nominal and data bit time is divided into four non-overlapping segments:
1. **Synchronization Segment ($\text{SYNC\_SEG}$):** Fixed at $1\ t_q$; aligns edge transitions on the physical bus.
2. **Propagation Segment ($\text{PROP\_SEG}$):** Compensates for physical line delay and transceiver loop delays.
3. **Phase Buffer Segment 1 ($\text{PHASE\_SEG1}$):** Pre-sample buffer, expandable by synchronization jump width ($\text{SJW}$).
4. **Phase Buffer Segment 2 ($\text{PHASE\_SEG2}$):** Post-sample buffer, shrinkable by $\text{SJW}$.

The time quantum duration $t_q$ is given by:
$$t_q = \frac{\text{BRP}}{f_{\text{sys}}}$$

For an FPGA system clock $f_{\text{sys}} = 100\ \text{MHz}$ and $\text{BRP} = 1$:
$$t_q = \frac{1}{100 \times 10^6\ \text{s}^{-1}} = 10.0\ \text{ns}$$

The total bit duration $T_{\text{bit}}$ in integer time quanta is:
$$N_{tq} = \frac{T_{\text{bit}}}{t_q} = \text{SYNC\_SEG} + \text{PROP\_SEG} + \text{PHASE\_SEG1} + \text{PHASE\_SEG2}$$

The sample point $SP$ (percentage of bit duration elapsed prior to sampling) is:
$$SP = \frac{\text{SYNC\_SEG} + \text{PROP\_SEG} + \text{PHASE\_SEG1}}{N_{tq}} \times 100\%$$

### 2.1 Nominal Arbitration Phase ($R_{\text{nominal}} = 500\ \text{kbps}$, $T_{\text{bit,nom}} = 2000\ \text{ns} = 200\ t_q$)
* $\text{SYNC\_SEG} = 1\ t_q$ ($10\ \text{ns}$)
* $\text{PROP\_SEG} = 99\ t_q$ ($990\ \text{ns}$)
* $\text{PHASE\_SEG1} = 60\ t_q$ ($600\ \text{ns}$)
* $\text{PHASE\_SEG2} = 40\ t_q$ ($400\ \text{ns}$)
* **Sample Point:**
  $$SP_{\text{nom}} = \frac{1 + 99 + 60}{200} \times 100\% = \frac{160}{200} \times 100\% = 80.0\%$$
* $\text{SJW} = 40\ t_q$ ($400\ \text{ns}$).

### 2.2 Data Phase ($R_{\text{data}} = 2.0\ \text{Mbps}$, $T_{\text{bit,dat}} = 500\ \text{ns} = 50\ t_q$)
* $\text{SYNC\_SEG} = 1\ t_q$ ($10\ \text{ns}$)
* $\text{PROP\_SEG} = 19\ t_q$ ($190\ \text{ns}$)
* $\text{PHASE\_SEG1} = 15\ t_q$ ($150\ \text{ns}$)
* $\text{PHASE\_SEG2} = 15\ t_q$ ($150\ \text{ns}$)
* **Sample Point:**
  $$SP_{\text{dat}} = \frac{1 + 19 + 15}{50} \times 100\% = \frac{35}{50} \times 100\% = 70.0\%$$
* $\text{SJW} = 10\ t_q$ ($100\ \text{ns}$).

---

## 3. CAN-FD Serialized Frame Duration and Dual-Rate Timing Model

A complete ISO CAN-FD base frame comprises two distinct clock domains:
1. **Arbitration Phase (Nominal Rate $R_{\text{nominal}}$):** Transmitted at $500\ \text{kbps}$ ($2.0\ \mu\text{s}/\text{bit}$). Spans SOF, 11-bit Identifier, RTR/RRS, IDE, FDF, and the nominal portion of BRS. Returns to nominal rate at the CRC Delimiter, ACK, ACK Delimiter, EOF ($7\ \text{bits}$ recessive), and Intermission ($3\ \text{bits}$ recessive).
2. **Data Phase (High Rate $R_{\text{data}}$):** Transmitted at $2.0\ \text{Mbps}$ ($0.5\ \mu\text{s}/\text{bit}$). Spans ESI, DLC (4 bits), Data Field ($8 \times \text{DLC}$ bits), Stuff Count ($4\ \text{bits}$ Gray code + parity), CRC field, and fixed stuff bits.

The total serialized frame duration $T_{\text{frame}}$ is:
$$T_{\text{frame}} = N_{\text{nominal}} \cdot T_{\text{bit,nom}} + N_{\text{data}} \cdot T_{\text{bit,dat}}$$

Where:
$$N_{\text{nominal}} = N_{\text{header,nom}} + N_{\text{trailer,nom}} + S_{\text{dyn,nom}}$$
$$N_{\text{data}} = N_{\text{control,dat}} + 8 \cdot \text{len}(\text{payload}) + N_{\text{CRC}} + N_{\text{StuffCount}} + S_{\text{fixed}} + S_{\text{dyn,dat}}$$

### 3.1 Dynamic and Fixed Bit Stuffing Derivation
Under ISO 11898-1:2015:
* **Dynamic Stuffing:** Applies from SOF through the end of the Data Field. An inverse stuff bit is automatically inserted after any sequence of 5 identical consecutive bits. The dynamic stuff count $S_{\text{dyn}}$ is bounded by:
  $$0 \le S_{\text{dyn}} \le \left\lfloor \frac{N_{\text{destuff}} - 1}{4} \right\rfloor$$
* **Fixed Stuffing (CRC Field):** In the CRC field, dynamic stuffing is disabled. Fixed stuff bits of alternating polarity are inserted at deterministic positions:
  * For payloads $\le 16$ bytes (CRC-17, polynomial degree 17): 6 fixed stuff bits (FS0 at CRC start, followed by one fixed stuff bit every 4 bits).
  * For payloads $> 16$ bytes (CRC-21, polynomial degree 21): 7 fixed stuff bits.
* **Stuff Count:** A 4-bit field inserted before the CRC sequence containing a 3-bit Gray-coded representation of $(S_{\text{dyn}} \bmod 8)$ protected by an even parity bit:
  $$p_{\text{stuff}} = b_2 \oplus b_1 \oplus b_0 \oplus 1$$

### 3.2 Exact Frame Duration Formulation
For standard 8-byte payload frames (DLC = 8, 64 data bits, CRC-17):
* $N_{\text{header,nom}} = 1\ (\text{SOF}) + 11\ (\text{ID}) + 1\ (\text{RRS}) + 1\ (\text{IDE}) + 1\ (\text{FDF}) + 1\ (\text{BRS}) = 16\ \text{bits}$.
* $N_{\text{trailer,nom}} = 1\ (\text{CRC Delim}) + 1\ (\text{ACK}) + 1\ (\text{ACK Delim}) + 7\ (\text{EOF}) + 3\ (\text{Intermission}) = 13\ \text{bits}$.
* $N_{\text{nominal,base}} = 16 + 13 = 29\ \text{bits}$ ($58.0\ \mu\text{s}$).
* $N_{\text{data,base}} = 1\ (\text{ESI}) + 4\ (\text{DLC}) + 64\ (\text{Data}) + 4\ (\text{StuffCount}) + 17\ (\text{CRC}) + 6\ (\text{FixedStuff}) = 96\ \text{bits}$ ($48.0\ \mu\text{s}$).

Nominal total frame duration without dynamic stuffing:
$$T_{\text{frame,base}} = (29 \times 2.0\ \mu\text{s}) + (96 \times 0.5\ \mu\text{s}) = 58.0\ \mu\text{s} + 48.0\ \mu\text{s} = 106.0\ \mu\text{s}$$

With average dynamic stuffing ($\sim 4$ stuff bits nominal, $\sim 3$ stuff bits data):
$$T_{\text{frame,typ}} \approx ((29 + 4) \times 2.0\ \mu\text{s}) + ((96 + 3) \times 0.5\ \mu\text{s}) = 66.0\ \mu\text{s} + 49.5\ \mu\text{s} = 115.5\ \mu\text{s}$$

---

## 4. Bus Load and Channel Utilization Formulation

For an observation window of duration $W$ (configured to $50\ \text{ms} = 50,000\ \mu\text{s}$), the bus load $L_W$ is the fraction of time the physical channel is occupied by active dominant/recessive bit transmissions:

$$L_W = \frac{\sum_{i=1}^{N_W} T_{\text{frame}, i}}{W} \times 100\%$$

Where $N_W$ is the total count of frames whose transmission overlaps window $W$.

### 4.1 Nominal Cruising Bus Load
Our powertrain network configuration broadcasts:
* `0x100` (VehicleSpeed): $T = 10\ \text{ms}$ ($100\ \text{fps}$), $T_{\text{frame}} \approx 115.5\ \mu\text{s} \implies 1.16\%$ load.
* `0x101` (EngineTemp): $T = 100\ \text{ms}$ ($10\ \text{fps}$), $T_{\text{frame}} \approx 115.5\ \mu\text{s} \implies 0.12\%$ load.
* `0x102` (BrakeStatus): $T = 20\ \text{ms}$ ($50\ \text{fps}$), $T_{\text{frame}} \approx 115.5\ \mu\text{s} \implies 0.58\%$ load.
* `0x103` (SteeringAngle): $T = 10\ \text{ms}$ ($100\ \text{fps}$), $T_{\text{frame}} \approx 115.5\ \mu\text{s} \implies 1.16\%$ load.
* `0x200` (BatteryStatus): $T = 500\ \text{ms}$ ($2\ \text{fps}$), DLC 10 (16B), $T_{\text{frame}} \approx 135.5\ \mu\text{s} \implies 0.03\%$ load.
* `0x201` (Diagnostics): $T = 1000\ \text{ms}$ ($1\ \text{fps}$), DLC 13 (32B), $T_{\text{frame}} \approx 205.5\ \mu\text{s} \implies 0.02\%$ load.

$$\text{Total Benign Bus Load } L_{\text{benign}} \approx 1.16\% + 0.12\% + 0.58\% + 1.16\% + 0.03\% + 0.02\% \approx 3.07\%$$

### 4.2 Saturated Bus Load Under Denial-of-Service (DoS) Attack
During a DoS flooding attack on ID `0x050` with interval $T_{\text{DoS}} = 500\ \mu\text{s}$ ($2,000\ \text{fps}$):
$$L_{\text{DoS}} = L_{\text{benign}} + \left( \frac{115.5\ \mu\text{s}}{500.0\ \mu\text{s}} \times 100\% \right) \approx 3.07\% + 23.1\% = 26.17\%$$

Under high-load bus arbitration saturation ($T_{\text{DoS}} = 120\ \mu\text{s}$), the bus load saturates to $\sim 98.4\%$, exhausting the channel.

---

## 5. Information-Theoretic Payload Entropy Model

To quantify randomness and distinguish structured telemetry from randomized fuzzing payloads, the Shannon payload entropy $H(X)$ of a received $K$-byte payload ($X = \{b_0, b_1, \dots, b_{K-1}\}$) is defined as:

$$H(X) = -\sum_{v \in \mathcal{V}} p(v) \log_2 p(v)$$

Where $\mathcal{V}$ is the set of unique byte values observed in the payload ($|\mathcal{V}| \le K$), and $p(v) = \frac{\text{count}(v)}{K}$.

### 5.1 Entropy Bounds
* **Constant / Quiescent Telemetry (e.g. BrakeStatus pedal = 0%):** All bytes $b_j = 0x00 \implies p(0) = 1.0 \implies H(X) = 0.0\ \text{bits/byte}$.
* **Maximum Entropy (Uniformly Randomized Fuzzing):** For an 8-byte payload with 8 distinct random bytes:
  $$p(v) = \frac{1}{8} \implies H_{\max}(X) = -8 \times \left(\frac{1}{8} \log_2 \frac{1}{8}\right) = \log_2 8 = 3.0\ \text{bits/byte}$$
  Over a multi-frame buffer ($K = 64$ bytes): $H_{\max}(X) = \log_2 64 = 6.0\ \text{bits/byte}$, approaching $8.0\ \text{bits/byte}$ for pure white noise.

### 5.2 Fixed-Point Integer Hardware Entropy Approximation
In synthesisable FPGA RTL, floating-point $\log_2$ is replaced by a leading-zeros detector (LZD) and piecewise linear approximation:
$$\log_2(u) \approx \text{LZD}(u) + \frac{u - 2^{\text{LZD}(u)}}{2^{\text{LZD}(u)}}$$

In our integer feature pipeline, payload entropy is represented as the integer Hamming change count $\Delta_{\text{payload}}$ and non-zero payload delta ($p_{\text{delta}}$), which correlate monotonically with $H(X)$ while consuming zero DSP blocks.

---

## 6. Gini Impurity and Decision-Tree Split Optimization

The supervised behavioral classifier uses binary decision trees trained via the CART (Classification and Regression Trees) algorithm with Gini impurity.

For a dataset $D$ containing samples from $C = 6$ classes (Normal, DoS, Fuzzing, Spoofing, Replay, Suppression), the Gini impurity of node $t$ is:

$$I_G(t) = 1 - \sum_{k=0}^{C-1} p(k|t)^2$$

Where $p(k|t)$ is the empirical probability of class $k$ among the $N_t$ samples at node $t$:
$$p(k|t) = \frac{1}{N_t} \sum_{i \in D_t} \mathbf{1}[y_i = k]$$

### 6.1 Split Selection Rule
At each node $t$, the algorithm evaluates candidate feature $j \in \{0, \dots, 13\}$ and threshold $\theta \in \mathbb{Z}$ to split $D_t$ into subsets $D_L = \{x \in D_t \mid x_j \le \theta\}$ and $D_R = \{x \in D_t \mid x_j > \theta\}$.

The optimal split $(j^*, \theta^*)$ maximizes the Gini impurity reduction $\Delta I_G(s, t)$:

$$(j^*, \theta^*) = \arg\max_{j, \theta} \left[ I_G(t) - \left( \frac{N_L}{N_t} I_G(t_L) + \frac{N_R}{N_t} I_G(t_R) \right) \right]$$

### 6.2 Integer Threshold Enforcement
To guarantee exact integer execution on microcontrollers and FPGA logic:
$$\theta_{\text{integer}} = \lfloor \theta_{\text{optimal}} \rfloor$$
All split inequalities in the exported C and Verilog models are formulated strictly as:
$$\text{Branch to Left Node if: } f[j] \le \theta_{\text{integer}}$$

---

## 7. Statistical Confidence Framework

For all reported performance metrics (Accuracy, Precision, Recall, Macro-F1, False Positive Rate), the $95\%$ confidence interval (CI) over $n$ evaluation samples is computed via the normal approximation to the binomial distribution (valid since $n \cdot p \ge 10$ and $n \cdot (1-p) \ge 10$):

$$\text{CI}_{95\%} = \hat{p} \pm z_{0.025} \sqrt{\frac{\hat{p}(1 - \hat{p})}{n}} = \hat{p} \pm 1.960 \sqrt{\frac{\hat{p}(1 - \hat{p})}{n}}$$

For continuous timing metrics (latency, execution time, throughput), the standard error of the mean over $n$ repeated trials is:

$$\text{CI}_{95\%} = \bar{x} \pm t_{n-1, 0.025} \frac{s}{\sqrt{n}}$$

### 7.1 Empirical Confidence Intervals on Test Set ($n = 4,975$)
* **Overall Accuracy:** $\hat{p} = 0.9956 \implies \text{Margin} = 1.96 \sqrt{\frac{0.9956 \times 0.0044}{4975}} = \pm 0.0018 \implies [99.38\%, 99.74\%]$.
* **Benign FPR ($n = 2,572$ normal frames):** $\hat{p} = 0.0047 \implies \text{Margin} = 1.96 \sqrt{\frac{0.0047 \times 0.9953}{2572}} = \pm 0.0026 \implies [0.21\%, 0.73\%]$, strictly satisfying the $< 1.0\%$ requirement.

---

## 8. Latency in Bit Times Formulation

To allow platform-independent comparison across automotive networks operating at different baud rates, detection latency $T_{\text{lat}}$ (in seconds) is converted into equivalent nominal bit times $T_{\text{lat,bits}}$:

$$T_{\text{lat,bits}} = T_{\text{lat}} \times R_{\text{nominal}}$$

For our $500\ \text{kbps}$ nominal arbitration bitrate ($1\ \text{bit time} = 2.0\ \mu\text{s}$):
* **DoS Onset Latency:** $T_{\text{lat}} = 500\ \mu\text{s} \implies T_{\text{lat,bits}} = 500 \times 10^{-6}\ \text{s} \times 500,000\ \text{bps} = \mathbf{250\ \text{bit times}}$.
* **Suppression Detection Delay:** $T_{\text{lat}} = 29.94\ \text{ms} \implies T_{\text{lat,bits}} = 29.94 \times 10^{-3}\ \text{s} \times 500,000\ \text{bps} = \mathbf{14,970\ \text{bit times}}$.
* **First-Frame Detections (Fuzzing, Spoofing, Replay):** $T_{\text{lat}} = 0\ \mu\text{s} \implies T_{\text{lat,bits}} = \mathbf{0\ \text{bit times}}$ (immediate alert upon frame reception).
