// ============================================================================
// Top-Level CAN-FD Bit-Stream Intrusion Detection System (IDS)
// Target Architecture: Xilinx Artix-7 (xc7a35tcsg324-1)
// System Clock: 100 MHz (10.0 ns)
// Combines physical bit sampling, ISO 11898-1:2015 protocol verification,
// fixed-point feature extraction, and single-cycle decision-tree classification.
// ============================================================================

`timescale 1ns / 1ps
`include "canfd_pkg.vh"

module canfd_ids_top (
    input  wire        clk,                  // 100 MHz System Clock
    input  wire        rst_n,                // Active-low Synchronous Reset
    input  wire        can_rx,               // Physical RX pin from CAN-FD Transceiver
    output reg         alert_valid,          // 1-cycle strobe on intrusion/anomaly event
    output reg         alert_dos,            // High on DoS attack classification
    output reg         alert_fuzzing,        // High on Fuzzing attack classification
    output reg         alert_spoofing,       // High on Spoofing attack classification
    output reg         alert_replay,         // High on Replay attack classification
    output reg         alert_suppression,    // High on Periodic Frame Suppression
    output reg         alert_protocol_error, // High on CRC or Bit-Stuffing corruption
    output wire [2:0]  detected_class,       // Active predicted class index
    output wire [10:0] last_frame_id,        // Last parsed 11-bit CAN ID
    output wire [3:0]  last_frame_dlc,       // Last parsed DLC code
    output reg  [31:0] total_frames,         // Cumulative frame counter
    output reg  [31:0] total_alerts          // Cumulative alert counter
);

    // Internal Interconnect Wires
    wire rx_sync;
    wire falling_edge;
    wire rising_edge;

    wire sample_point_pulse;
    wire bit_sample;
    wire bit_end_pulse;

    wire destuffed_bit;
    wire destuffed_valid;
    wire stuff_error;

    wire data_rate_active;
    wire [1:0] stuffing_mode;
    wire bus_idle;
    wire crc_init;
    wire crc_enable;
    wire crc_in_bit;
    wire use_crc21;
    wire crc_check_pulse;
    wire [20:0] received_crc;
    wire [20:0] computed_crc;
    wire crc_match;
    wire crc_error;

    wire frame_valid_pulse;
    wire [10:0] frame_id;
    wire [3:0]  frame_dlc;
    wire [511:0] payload_data;
    wire [6:0]  payload_len_bytes;
    wire protocol_error_pulse;

    wire features_valid_pulse;
    wire signed [31:0] f0_frame_id;
    wire signed [31:0] f1_frame_dlc;
    wire signed [31:0] f2_payload_delta;
    wire signed [31:0] f3_inter_arrival;
    wire signed [31:0] f4_period_deviation;
    wire signed [31:0] f5_id_rate;
    wire signed [31:0] f6_total_bus_rate;
    wire signed [31:0] f7_id_seen_before;
    wire signed [31:0] f8_dlc_mismatch;
    wire signed [31:0] f9_payload_change_count;
    wire signed [31:0] f10_protocol_error_count;
    wire signed [31:0] f11_missing_frame_count;
    wire signed [31:0] f12_replay_similarity;
    wire signed [31:0] f13_duplicate_count;

    wire class_valid_out;
    wire [2:0] predicted_class;

    assign detected_class = predicted_class;
    assign last_frame_id  = frame_id;
    assign last_frame_dlc = frame_dlc;

    // Suppress unused signal warnings for unused top-level interconnects
    wire _unused_signals;
    assign _unused_signals = rising_edge ^ bit_end_pulse ^ (|computed_crc) ^ (|payload_len_bytes);

    // 1. Physical Line Synchronizer & Glitch Filter
    canfd_synchronizer u_sync (
        .clk          (clk),
        .rst_n        (rst_n),
        .can_rx_async (can_rx),
        .rx_sync      (rx_sync),
        .falling_edge (falling_edge),
        .rising_edge  (rising_edge)
    );

    // 2. Dual-Rate Bit Sampler (500 kbps @ 80% SP / 2.0 Mbps @ 70% SP)
    canfd_bit_sampler u_sampler (
        .clk               (clk),
        .rst_n             (rst_n),
        .rx_sync           (rx_sync),
        .falling_edge      (falling_edge),
        .data_rate_active  (data_rate_active),
        .bus_idle          (bus_idle),
        .sample_point_pulse(sample_point_pulse),
        .bit_sample        (bit_sample),
        .bit_end_pulse     (bit_end_pulse)
    );

    // 3. Dynamic and Fixed Bit Destuffer
    canfd_destuffer u_destuffer (
        .clk               (clk),
        .rst_n             (rst_n),
        .sample_point_pulse(sample_point_pulse),
        .bit_sample        (bit_sample),
        .stuffing_mode     (stuffing_mode),
        .destuffed_bit     (destuffed_bit),
        .destuffed_valid   (destuffed_valid),
        .stuff_error       (stuff_error)
    );

    // 4. Dual CRC Engine (CRC-17 & CRC-21)
    canfd_crc u_crc (
        .clk            (clk),
        .rst_n          (rst_n),
        .crc_init       (crc_init),
        .crc_enable     (crc_enable),
        .crc_in_bit     (crc_in_bit),
        .use_crc21      (use_crc21),
        .crc_check_pulse(crc_check_pulse),
        .received_crc   (received_crc),
        .crc_match      (crc_match),
        .crc_error      (crc_error),
        .computed_crc   (computed_crc)
    );

    // 5. Frame Parser State Machine
    canfd_frame_parser u_parser (
        .clk                 (clk),
        .rst_n               (rst_n),
        .destuffed_bit       (destuffed_bit),
        .destuffed_valid     (destuffed_valid),
        .stuff_error         (stuff_error),
        .crc_match           (crc_match),
        .crc_error           (crc_error),
        .data_rate_active    (data_rate_active),
        .stuffing_mode       (stuffing_mode),
        .bus_idle            (bus_idle),
        .crc_init            (crc_init),
        .crc_enable          (crc_enable),
        .crc_in_bit          (crc_in_bit),
        .use_crc21           (use_crc21),
        .crc_check_pulse     (crc_check_pulse),
        .received_crc        (received_crc),
        .frame_valid_pulse   (frame_valid_pulse),
        .frame_id            (frame_id),
        .frame_dlc           (frame_dlc),
        .payload_data        (payload_data),
        .payload_len_bytes   (payload_len_bytes),
        .protocol_error_pulse(protocol_error_pulse)
    );

    // 6. CAM-based Hardware Feature Extractor
    canfd_feature_extractor u_features (
        .clk                    (clk),
        .rst_n                  (rst_n),
        .frame_valid_pulse      (frame_valid_pulse),
        .frame_id               (frame_id),
        .frame_dlc              (frame_dlc),
        .payload_data           (payload_data),
        .protocol_error_pulse   (protocol_error_pulse),
        .features_valid_pulse   (features_valid_pulse),
        .f0_frame_id            (f0_frame_id),
        .f1_frame_dlc           (f1_frame_dlc),
        .f2_payload_delta       (f2_payload_delta),
        .f3_inter_arrival       (f3_inter_arrival),
        .f4_period_deviation    (f4_period_deviation),
        .f5_id_rate             (f5_id_rate),
        .f6_total_bus_rate      (f6_total_bus_rate),
        .f7_id_seen_before      (f7_id_seen_before),
        .f8_dlc_mismatch        (f8_dlc_mismatch),
        .f9_payload_change_count(f9_payload_change_count),
        .f10_protocol_error_count(f10_protocol_error_count),
        .f11_missing_frame_count(f11_missing_frame_count),
        .f12_replay_similarity  (f12_replay_similarity),
        .f13_duplicate_count    (f13_duplicate_count)
    );

    // 7. Single-Cycle Pipelined Decision Tree Classifier
    canfd_decision_tree u_tree (
        .clk                    (clk),
        .rst_n                  (rst_n),
        .eval_valid_in          (features_valid_pulse),
        .f0_frame_id            (f0_frame_id),
        .f1_frame_dlc           (f1_frame_dlc),
        .f2_payload_delta       (f2_payload_delta),
        .f3_inter_arrival       (f3_inter_arrival),
        .f4_period_deviation    (f4_period_deviation),
        .f5_id_rate             (f5_id_rate),
        .f6_total_bus_rate      (f6_total_bus_rate),
        .f7_id_seen_before      (f7_id_seen_before),
        .f8_dlc_mismatch        (f8_dlc_mismatch),
        .f9_payload_change_count(f9_payload_change_count),
        .f10_protocol_error_count(f10_protocol_error_count),
        .f11_missing_frame_count(f11_missing_frame_count),
        .f12_replay_similarity  (f12_replay_similarity),
        .f13_duplicate_count    (f13_duplicate_count),
        .class_valid_out        (class_valid_out),
        .predicted_class        (predicted_class)
    );

    // 8. Hardware Safety Supervisor: Deadline Timer for BrakeStatus (0x102)
    reg [23:0] brake_deadline_timer;
    reg brake_suppressed_alert;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            brake_deadline_timer   <= 24'd0;
            brake_suppressed_alert <= 1'b0;
        end else begin
            if (frame_valid_pulse && (frame_id == 11'h102)) begin
                brake_deadline_timer   <= 24'd0;
                brake_suppressed_alert <= 1'b0;
            end else if (brake_deadline_timer >= 24'd3_000_000) begin
                // 30 ms deadline expired (3x nominal 10 ms period @ 100 MHz)
                brake_suppressed_alert <= 1'b1;
            end else begin
                brake_deadline_timer <= brake_deadline_timer + 1'b1;
            end
        end
    end

    // Alert Generation and Metric Counters
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            alert_valid          <= 1'b0;
            alert_dos            <= 1'b0;
            alert_fuzzing        <= 1'b0;
            alert_spoofing       <= 1'b0;
            alert_replay         <= 1'b0;
            alert_suppression    <= 1'b0;
            alert_protocol_error <= 1'b0;
            total_frames         <= 32'd0;
            total_alerts         <= 32'd0;
        end else begin
            alert_valid          <= 1'b0;
            alert_dos            <= 1'b0;
            alert_fuzzing        <= 1'b0;
            alert_spoofing       <= 1'b0;
            alert_replay         <= 1'b0;
            alert_suppression    <= 1'b0;
            alert_protocol_error <= 1'b0;

            if (frame_valid_pulse) begin
                total_frames <= total_frames + 1'b1;
            end

            if (protocol_error_pulse) begin
                alert_valid          <= 1'b1;
                alert_protocol_error <= 1'b1;
                total_alerts         <= total_alerts + 1'b1;
            end else if (brake_suppressed_alert && (brake_deadline_timer == 24'd3_000_000)) begin
                alert_valid       <= 1'b1;
                alert_suppression <= 1'b1;
                total_alerts      <= total_alerts + 1'b1;
            end else if (class_valid_out && (predicted_class != `CLASS_NORMAL)) begin
                alert_valid  <= 1'b1;
                total_alerts <= total_alerts + 1'b1;
                case (predicted_class)
                    `CLASS_DOS:         alert_dos         <= 1'b1;
                    `CLASS_FUZZING:     alert_fuzzing     <= 1'b1;
                    `CLASS_SPOOFING:    alert_spoofing    <= 1'b1;
                    `CLASS_REPLAY:      alert_replay      <= 1'b1;
                    `CLASS_SUPPRESSION: alert_suppression <= 1'b1;
                    default: ;
                endcase
            end
        end
    end

endmodule
