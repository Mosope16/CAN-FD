// ============================================================================
// CAN-FD Intrusion Detection System (IDS) Package Header
// Target: Xilinx Artix-7 (xc7a35tcsg324-1)
// System Clock: 100 MHz (10.0 ns period)
// ============================================================================

`ifndef CANFD_PKG_VH
`define CANFD_PKG_VH

// Timing Configuration (100 MHz System Clock)
`define SYS_CLK_HZ            32'd100_000_000
`define TIME_QUANTA_NS        10

// Nominal Phase (500 kbps: 2000 ns bit time = 200 clock cycles @ 100 MHz)
`define NOMINAL_BIT_CYCLES    8'd200
`define NOMINAL_SAMPLE_CYCLE  8'd160   // 80.0% Sample Point

// Data Phase (2.0 Mbps: 500 ns bit time = 50 clock cycles @ 100 MHz)
`define DATA_BIT_CYCLES       8'd50
`define DATA_SAMPLE_CYCLE     8'd35    // 70.0% Sample Point

// CAN-FD Protocol Constants
`define CANFD_MAX_PAYLOAD_BITS 512     // 64 Bytes
`define CANFD_MAX_PAYLOAD_BYTES 7'd64
`define CANFD_CRC17_POLY       17'h1685B // x^17 + x^16 + x^14 + x^13 + x^11 + x^6 + x^4 + x^3 + x^1 + 1
`define CANFD_CRC21_POLY       21'h302899 // x^21 + x^20 + x^13 + x^11 + x^7 + x^4 + x^3 + 1
`define CANFD_CRC17_INIT       17'h10000 // (1 << 16)
`define CANFD_CRC21_INIT       21'h100000 // (1 << 20)

// Attack Classification Labels
`define CLASS_NORMAL          3'd0
`define CLASS_DOS             3'd1
`define CLASS_FUZZING         3'd2
`define CLASS_SPOOFING        3'd3
`define CLASS_REPLAY          3'd4
`define CLASS_SUPPRESSION     3'd5
`define CLASS_PROTOCOL_ERR    3'd6

// Maximum Monitored IDs in Hardware Content-Addressable Memory (CAM)
`define CAM_ENTRIES           4'd8

`endif // CANFD_PKG_VH
