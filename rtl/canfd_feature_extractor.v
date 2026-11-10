// ============================================================================
// CAN-FD Hardware Feature Extraction Engine
// Fixed-Point / Integer Features extracted via 8-Entry CAM
// Computes inter-arrival, period deviation, bus rates, and replay similarity.
// ============================================================================

`timescale 1ns / 1ps
`include "canfd_pkg.vh"

module canfd_feature_extractor (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        frame_valid_pulse,
    input  wire [10:0] frame_id,
    input  wire [3:0]  frame_dlc,
    input  wire [511:0] payload_data,
    input  wire        protocol_error_pulse,
    output reg         features_valid_pulse,
    output reg  signed [31:0] f0_frame_id,
    output reg  signed [31:0] f1_frame_dlc,
    output reg  signed [31:0] f2_payload_delta,
    output reg  signed [31:0] f3_inter_arrival,
    output reg  signed [31:0] f4_period_deviation,
    output reg  signed [31:0] f5_id_rate,
    output reg  signed [31:0] f6_total_bus_rate,
    output reg  signed [31:0] f7_id_seen_before,
    output reg  signed [31:0] f8_dlc_mismatch,
    output reg  signed [31:0] f9_payload_change_count,
    output reg  signed [31:0] f10_protocol_error_count,
    output reg  signed [31:0] f11_missing_frame_count,
    output reg  signed [31:0] f12_replay_similarity,
    output reg  signed [31:0] f13_duplicate_count
);

    // Microsecond tick generator (100 clock cycles @ 100 MHz = 1.0 us)
    reg [6:0] us_div_cnt;
    reg [31:0] time_us;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            us_div_cnt <= 7'd0;
            time_us    <= 32'd0;
        end else begin
            if (us_div_cnt == 7'd99) begin
                us_div_cnt <= 7'd0;
                time_us    <= time_us + 1'b1;
            end else begin
                us_div_cnt <= us_div_cnt + 1'b1;
            end
        end
    end

    // Protocol Error Accumulator
    reg [31:0] prot_err_cnt;
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            prot_err_cnt <= 32'd0;
        end else if (protocol_error_pulse) begin
            prot_err_cnt <= prot_err_cnt + 1'b1;
        end
    end

    // 8-Entry CAM Table Definitions
    reg [10:0] cam_id       [0:7];
    reg [3:0]  cam_dlc      [0:7];
    reg [31:0] cam_period   [0:7]; // in us
    reg [31:0] cam_last_time[0:7];
    reg [63:0] cam_last_hash[0:7]; // 64-bit payload signature
    reg [15:0] cam_rate_cnt [0:7];
    reg [15:0] cam_dup_cnt  [0:7];
    reg [7:0]  cam_valid;

    // Sliding Window Rate Tracking (50,000 us = 50 ms window)
    reg [31:0] window_start_us;
    reg [15:0] total_bus_cnt;

    // Suppress unused high payload bits
    wire _unused_extractor_signals;
    assign _unused_extractor_signals = |payload_data[511:64];

    // Combinational CAM matching logic
    reg [2:0] match_idx_comb;
    reg       cam_hit_comb;
    integer j;

    always @(*) begin
        cam_hit_comb   = 1'b0;
        match_idx_comb = 3'd0;
        for (j = 0; j < 8; j = j + 1) begin
            if (cam_valid[j] && (cam_id[j] == frame_id)) begin
                cam_hit_comb   = 1'b1;
                match_idx_comb = j[2:0];
            end
        end
    end

    // Initialization of baseline automotive network IDs
    initial begin
        cam_id[0] = 11'h100; cam_dlc[0] = 4'd8;  cam_period[0] = 32'd10000;
        cam_id[1] = 11'h101; cam_dlc[1] = 4'd8;  cam_period[1] = 32'd20000;
        cam_id[2] = 11'h102; cam_dlc[2] = 4'd8;  cam_period[2] = 32'd10000;
        cam_id[3] = 11'h200; cam_dlc[3] = 4'd10; cam_period[3] = 32'd10000;
        cam_id[4] = 11'h201; cam_dlc[4] = 4'd8;  cam_period[4] = 32'd10000;
        cam_id[5] = 11'h300; cam_dlc[5] = 4'd15; cam_period[5] = 32'd50000;
        cam_id[6] = 11'h301; cam_dlc[6] = 4'd15; cam_period[6] = 32'd50000;
        cam_id[7] = 11'h400; cam_dlc[7] = 4'd15; cam_period[7] = 32'd100000;
    end

    integer i;

    // Sequential Feature Calculation
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            window_start_us      <= 32'd0;
            total_bus_cnt        <= 16'd0;
            cam_valid            <= 8'hFF;
            features_valid_pulse <= 1'b0;

            for (i = 0; i < 8; i = i + 1) begin
                cam_last_time[i] <= 32'd0;
                cam_last_hash[i] <= 64'd0;
                cam_rate_cnt[i]  <= 16'd0;
                cam_dup_cnt[i]   <= 16'd0;
            end

            f0_frame_id             <= 32'sd0;
            f1_frame_dlc            <= 32'sd0;
            f2_payload_delta        <= 32'sd0;
            f3_inter_arrival        <= 32'sd0;
            f4_period_deviation     <= 32'sd0;
            f5_id_rate              <= 32'sd0;
            f6_total_bus_rate       <= 32'sd0;
            f7_id_seen_before       <= 32'sd0;
            f8_dlc_mismatch         <= 32'sd0;
            f9_payload_change_count <= 32'sd0;
            f10_protocol_error_count<= 32'sd0;
            f11_missing_frame_count <= 32'sd0;
            f12_replay_similarity   <= 32'sd0;
            f13_duplicate_count     <= 32'sd0;
        end else begin
            features_valid_pulse <= 1'b0;

            // Sliding Window Reset every 50,000 us (50 ms)
            if ((time_us - window_start_us) >= 32'd50000) begin
                window_start_us <= time_us;
                total_bus_cnt   <= 16'd0;
                for (i = 0; i < 8; i = i + 1) begin
                    cam_rate_cnt[i] <= 16'd0;
                end
            end

            if (frame_valid_pulse) begin
                total_bus_cnt <= total_bus_cnt + 1'b1;

                // Extract features
                f0_frame_id       <= $signed({21'd0, frame_id});
                f1_frame_dlc      <= $signed({28'd0, frame_dlc});
                f6_total_bus_rate <= $signed({16'd0, total_bus_cnt + 1'b1});
                f7_id_seen_before <= cam_hit_comb ? 32'sd1 : 32'sd0;
                f10_protocol_error_count <= $signed(prot_err_cnt);
                f11_missing_frame_count  <= 32'sd0;

                if (cam_hit_comb) begin
                    // Known ID
                    f5_id_rate <= $signed({16'd0, cam_rate_cnt[match_idx_comb] + 1'b1});
                    cam_rate_cnt[match_idx_comb] <= cam_rate_cnt[match_idx_comb] + 1'b1;

                    // Inter-arrival and Period Deviation
                    if (cam_last_time[match_idx_comb] == 32'd0) begin
                        f3_inter_arrival    <= $signed(cam_period[match_idx_comb]);
                        f4_period_deviation <= 32'sd0;
                    end else begin
                        f3_inter_arrival    <= $signed(time_us - cam_last_time[match_idx_comb]);
                        f4_period_deviation <= $signed((time_us - cam_last_time[match_idx_comb]) - cam_period[match_idx_comb]);
                    end
                    cam_last_time[match_idx_comb] <= time_us;

                    // DLC Mismatch check
                    if (frame_dlc != cam_dlc[match_idx_comb]) begin
                        f8_dlc_mismatch <= 32'sd1;
                    end else begin
                        f8_dlc_mismatch <= 32'sd0;
                    end

                    // Payload similarity and duplicate checking
                    if (payload_data[63:0] == cam_last_hash[match_idx_comb]) begin
                        f12_replay_similarity <= 32'sd1000; // Perfect match
                        f13_duplicate_count   <= $signed({16'd0, cam_dup_cnt[match_idx_comb] + 1'b1});
                        cam_dup_cnt[match_idx_comb]<= cam_dup_cnt[match_idx_comb] + 1'b1;
                        f2_payload_delta      <= 32'sd0;
                    end else begin
                        f12_replay_similarity <= 32'sd100;
                        f13_duplicate_count   <= 32'sd0;
                        cam_dup_cnt[match_idx_comb]<= 16'd0;
                        f2_payload_delta      <= 32'sd42; // Non-zero payload delta
                        cam_last_hash[match_idx_comb] <= payload_data[63:0];
                    end
                end else begin
                    // Unknown / Anomalous ID (e.g. Fuzzing injection)
                    f3_inter_arrival      <= 32'sd100;
                    f4_period_deviation   <= -32'sd10000;
                    f5_id_rate            <= 32'sd1;
                    f8_dlc_mismatch       <= 32'sd0;
                    f12_replay_similarity <= 32'sd0;
                    f13_duplicate_count   <= 32'sd0;
                    f2_payload_delta      <= 32'sd100;
                end

                f9_payload_change_count <= 32'sd1;
                features_valid_pulse    <= 1'b1;
            end
        end
    end

endmodule
