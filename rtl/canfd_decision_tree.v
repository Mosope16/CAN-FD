// ============================================================================
// CAN-FD Hardware Decision Tree Classifier
// Single-Cycle Combinational Inference Engine (Zero Floating-Point)
// Direct hardware translation of models/exported/classifier.c
// ============================================================================

`timescale 1ns / 1ps
`include "canfd_pkg.vh"

module canfd_decision_tree (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        eval_valid_in,
    input  wire signed [31:0] f0_frame_id,
    input  wire signed [31:0] f1_frame_dlc,
    input  wire signed [31:0] f2_payload_delta,
    input  wire signed [31:0] f3_inter_arrival,
    input  wire signed [31:0] f4_period_deviation,
    input  wire signed [31:0] f5_id_rate,
    input  wire signed [31:0] f6_total_bus_rate,
    input  wire signed [31:0] f7_id_seen_before,
    input  wire signed [31:0] f8_dlc_mismatch,
    input  wire signed [31:0] f9_payload_change_count,
    input  wire signed [31:0] f10_protocol_error_count,
    input  wire signed [31:0] f11_missing_frame_count,
    input  wire signed [31:0] f12_replay_similarity,
    input  wire signed [31:0] f13_duplicate_count,
    output reg         class_valid_out,
    output reg  [2:0]  predicted_class
);

    // Suppress unused parameter warnings for unused tree features
    wire [31:0] unused_features;
    assign unused_features = f0_frame_id ^ f1_frame_dlc ^ f2_payload_delta ^
                             f8_dlc_mismatch ^ f9_payload_change_count ^
                             f10_protocol_error_count ^ f11_missing_frame_count;

    // Pure combinational tree evaluation function
    function [2:0] evaluate_tree(
        input signed [31:0] in_f3,
        input signed [31:0] in_f4,
        input signed [31:0] in_f5,
        input signed [31:0] in_f6,
        input signed [31:0] in_f7,
        input signed [31:0] in_f12,
        input signed [31:0] in_f13
    );
        begin
            if (in_f5 <= 32'sd0) begin
                evaluate_tree = `CLASS_SUPPRESSION; // Class 5
            end else begin
                if (in_f7 <= 32'sd0) begin
                    if (in_f12 <= 32'sd507) begin
                        if (in_f6 <= 32'sd15) begin
                            evaluate_tree = `CLASS_FUZZING; // Class 2
                        end else begin
                            if (in_f3 <= 32'sd1000) begin
                                evaluate_tree = `CLASS_FUZZING; // Class 2
                            end else begin
                                evaluate_tree = `CLASS_FUZZING; // Class 2
                            end
                        end
                    end else begin
                        if (in_f6 <= 32'sd19) begin
                            evaluate_tree = `CLASS_DOS; // Class 1
                        end else begin
                            evaluate_tree = `CLASS_DOS; // Class 1
                        end
                    end
                end else begin
                    if (in_f4 <= -32'sd11428) begin
                        if (in_f4 <= -32'sd19633) begin
                            evaluate_tree = `CLASS_FUZZING; // Class 2
                        end else begin
                            if (in_f3 <= 32'sd6529) begin
                                if (in_f5 <= 32'sd10) begin
                                    evaluate_tree = `CLASS_NORMAL; // Class 0
                                end else begin
                                    evaluate_tree = `CLASS_SPOOFING; // Class 3
                                end
                            end else begin
                                if (in_f13 <= 32'sd0) begin
                                    evaluate_tree = `CLASS_SPOOFING; // Class 3
                                end else begin
                                    evaluate_tree = `CLASS_SPOOFING; // Class 3
                                end
                            end
                        end
                    end else begin
                        if (in_f4 <= -32'sd91) begin
                            if (in_f12 <= 32'sd875) begin
                                if (in_f6 <= 32'sd16) begin
                                    evaluate_tree = `CLASS_SPOOFING; // Class 3
                                end else begin
                                    evaluate_tree = `CLASS_NORMAL; // Class 0
                                end
                            end else begin
                                if (in_f3 <= 32'sd9424) begin
                                    evaluate_tree = `CLASS_REPLAY; // Class 4
                                end else begin
                                    evaluate_tree = `CLASS_REPLAY; // Class 4
                                end
                            end
                        end else begin
                            evaluate_tree = `CLASS_NORMAL; // Class 0
                        end
                    end
                end
            end
        end
    endfunction

    // Synchronous Registered Output
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            class_valid_out <= 1'b0;
            predicted_class <= `CLASS_NORMAL;
        end else begin
            class_valid_out <= eval_valid_in;
            if (eval_valid_in) begin
                predicted_class <= evaluate_tree(
                    f3_inter_arrival,
                    f4_period_deviation,
                    f5_id_rate,
                    f6_total_bus_rate,
                    f7_id_seen_before,
                    f12_replay_similarity,
                    f13_duplicate_count
                );
            end
        end
    end

endmodule
