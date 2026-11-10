// ============================================================================
// CAN-FD Dynamic and Fixed Destuffer
// ISO 11898-1:2015 Compliant Destuffing Engine
// Rejects stuffed bits and detects bit-stuffing corruption violations.
// ============================================================================

`timescale 1ns / 1ps

module canfd_destuffer (
    input  wire       clk,
    input  wire       rst_n,
    input  wire       sample_point_pulse,
    input  wire       bit_sample,
    input  wire [1:0] stuffing_mode,     // 2'b00: OFF, 2'b01: DYNAMIC, 2'b10: FIXED
    output reg        destuffed_bit,
    output reg        destuffed_valid,
    output reg        stuff_error
);

    localparam MODE_OFF     = 2'b00;
    localparam MODE_DYNAMIC = 2'b01;
    localparam MODE_FIXED   = 2'b10;

    reg [2:0] consecutive_cnt;
    reg       prev_bit;
    reg [2:0] fixed_cnt;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            consecutive_cnt <= 3'd0;
            prev_bit        <= 1'b1;
            fixed_cnt       <= 3'd0;
            destuffed_bit   <= 1'b1;
            destuffed_valid <= 1'b0;
            stuff_error     <= 1'b0;
        end else begin
            destuffed_valid <= 1'b0;
            stuff_error     <= 1'b0;

            if (sample_point_pulse) begin
                case (stuffing_mode)
                    MODE_OFF: begin
                        destuffed_bit   <= bit_sample;
                        destuffed_valid <= 1'b1;
                        consecutive_cnt <= 3'd0;
                        fixed_cnt       <= 3'd0;
                        prev_bit        <= bit_sample;
                    end

                    MODE_DYNAMIC: begin
                        if (consecutive_cnt == 3'd5) begin
                            // This bit is expected to be a dynamic stuff bit (inverted from prev_bit)
                            if (bit_sample == prev_bit) begin
                                // Bit-stuffing error! 6 consecutive identical bits
                                stuff_error     <= 1'b1;
                                destuffed_valid <= 1'b0;
                            end else begin
                                // Valid stuff bit discarded from frame data
                                destuffed_valid <= 1'b0;
                            end
                            consecutive_cnt <= 3'd0;
                            prev_bit        <= bit_sample;
                        end else begin
                            // Normal frame bit
                            destuffed_bit   <= bit_sample;
                            destuffed_valid <= 1'b1;
                            if (bit_sample == prev_bit) begin
                                consecutive_cnt <= consecutive_cnt + 1'b1;
                            end else begin
                                consecutive_cnt <= 3'd1;
                                prev_bit        <= bit_sample;
                            end
                        end
                    end

                    MODE_FIXED: begin
                        // In CRC field, fixed stuff bits appear at positions 0, 4, 8, 12, 16...
                        if (fixed_cnt == 3'd4) begin
                            // Fixed stuff bit expected: must be inverse of previous bit
                            if (bit_sample == prev_bit) begin
                                stuff_error     <= 1'b1;
                                destuffed_valid <= 1'b0;
                            end else begin
                                destuffed_valid <= 1'b0; // Discard stuff bit
                            end
                            fixed_cnt <= 3'd0;
                            prev_bit  <= bit_sample;
                        end else begin
                            destuffed_bit   <= bit_sample;
                            destuffed_valid <= 1'b1;
                            fixed_cnt       <= fixed_cnt + 1'b1;
                            prev_bit        <= bit_sample;
                        end
                    end

                    default: begin
                        destuffed_bit   <= bit_sample;
                        destuffed_valid <= 1'b1;
                    end
                endcase
            end
        end
    end

endmodule
