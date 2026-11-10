// ============================================================================
// CAN-FD Frame Parser State Machine
// Disassembles CAN-FD bitstream into header, DLC, payload, and CRC fields.
// Coordinates bit-rate switching (BRS) and stuffing modes.
// ============================================================================

`timescale 1ns / 1ps
`include "canfd_pkg.vh"

module canfd_frame_parser (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        destuffed_bit,
    input  wire        destuffed_valid,
    input  wire        stuff_error,
    input  wire        crc_match,
    input  wire        crc_error,
    output reg         data_rate_active,  // Controls baud rate (0: 500k, 1: 2M)
    output reg  [1:0]  stuffing_mode,     // 0: OFF, 1: DYNAMIC, 2: FIXED
    output reg         bus_idle,
    output reg         crc_init,
    output reg         crc_enable,
    output wire        crc_in_bit,
    output wire        use_crc21,
    output reg         crc_check_pulse,
    output wire [20:0] received_crc,
    output reg         frame_valid_pulse,
    output reg  [10:0] frame_id,
    output reg  [3:0]  frame_dlc,
    output reg  [511:0] payload_data,
    output reg  [6:0]  payload_len_bytes,
    output reg         protocol_error_pulse
);

    // FSM States
    localparam ST_IDLE       = 5'd0;
    localparam ST_ID         = 5'd2;
    localparam ST_RTR        = 5'd3;
    localparam ST_IDE        = 5'd4;
    localparam ST_FDF        = 5'd5;
    localparam ST_RES        = 5'd6;
    localparam ST_BRS        = 5'd7;
    localparam ST_ESI        = 5'd8;
    localparam ST_DLC        = 5'd9;
    localparam ST_DATA       = 5'd10;
    localparam ST_STUFF_CNT  = 5'd11;
    localparam ST_CRC        = 5'd12;
    localparam ST_CRC_DELIM  = 5'd13;
    localparam ST_ACK        = 5'd14;
    localparam ST_ACK_DELIM  = 5'd15;
    localparam ST_EOF        = 5'd16;
    localparam ST_ERROR_TRAP = 5'd17;

    reg [4:0] state;
    reg [9:0] bit_counter;
    reg [20:0] crc_shift;
    reg [3:0]  stuff_cnt_reg;
    reg        brs_latch;

    // Suppress unused signal warnings for parser debug registers
    wire _unused_parser_signals;
    assign _unused_parser_signals = crc_match ^ brs_latch ^ stuff_cnt_reg[3];

    assign crc_in_bit   = destuffed_bit;
    assign use_crc21    = (payload_len_bytes > 7'd16);
    assign received_crc = crc_shift;

    // DLC to Payload Bytes Decoder
    function [6:0] dlc_to_bytes(input [3:0] d);
        case (d)
            4'd0:  dlc_to_bytes = 7'd0;
            4'd1:  dlc_to_bytes = 7'd1;
            4'd2:  dlc_to_bytes = 7'd2;
            4'd3:  dlc_to_bytes = 7'd3;
            4'd4:  dlc_to_bytes = 7'd4;
            4'd5:  dlc_to_bytes = 7'd5;
            4'd6:  dlc_to_bytes = 7'd6;
            4'd7:  dlc_to_bytes = 7'd7;
            4'd8:  dlc_to_bytes = 7'd8;
            4'd9:  dlc_to_bytes = 7'd12;
            4'd10: dlc_to_bytes = 7'd16;
            4'd11: dlc_to_bytes = 7'd20;
            4'd12: dlc_to_bytes = 7'd24;
            4'd13: dlc_to_bytes = 7'd32;
            4'd14: dlc_to_bytes = 7'd48;
            4'd15: dlc_to_bytes = 7'd64;
            default: dlc_to_bytes = 7'd0;
        endcase
    endfunction

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state                <= ST_IDLE;
            bit_counter          <= 10'd0;
            data_rate_active     <= 1'b0;
            stuffing_mode        <= 2'b00;
            bus_idle             <= 1'b1;
            crc_init             <= 1'b0;
            crc_enable           <= 1'b0;
            crc_check_pulse      <= 1'b0;
            frame_valid_pulse    <= 1'b0;
            frame_id             <= 11'd0;
            frame_dlc            <= 4'd0;
            payload_data         <= 512'd0;
            payload_len_bytes    <= 7'd0;
            protocol_error_pulse <= 1'b0;
            crc_shift            <= 21'd0;
            stuff_cnt_reg        <= 4'd0;
            brs_latch            <= 1'b0;
        end else begin
            // Pulse resets
            crc_init             <= 1'b0;
            crc_enable           <= 1'b0;
            crc_check_pulse      <= 1'b0;
            frame_valid_pulse    <= 1'b0;
            protocol_error_pulse <= 1'b0;

            // Stuff error handling
            if (stuff_error && (state != ST_IDLE) && (state != ST_ERROR_TRAP)) begin
                protocol_error_pulse <= 1'b1;
                state                <= ST_ERROR_TRAP;
                data_rate_active     <= 1'b0;
                stuffing_mode        <= 2'b00;
                bit_counter          <= 10'd0;
            end else if (destuffed_valid) begin
                case (state)
                    ST_IDLE: begin
                        if (destuffed_bit == 1'b0) begin // Dominant SOF
                            bus_idle         <= 1'b0;
                            stuffing_mode    <= 2'b01; // Dynamic stuffing
                            crc_init         <= 1'b1;
                            crc_enable       <= 1'b1;
                            bit_counter      <= 10'd0;
                            frame_id         <= 11'd0;
                            payload_data     <= 512'd0;
                            state            <= ST_ID;
                        end else begin
                            bus_idle <= 1'b1;
                        end
                    end

                    ST_ID: begin
                        crc_enable <= 1'b1;
                        frame_id   <= {frame_id[9:0], destuffed_bit};
                        if (bit_counter == 10'd10) begin
                            bit_counter <= 10'd0;
                            state       <= ST_RTR;
                        end else begin
                            bit_counter <= bit_counter + 1'b1;
                        end
                    end

                    ST_RTR: begin
                        crc_enable  <= 1'b1;
                        bit_counter <= 10'd0;
                        state       <= ST_IDE;
                    end

                    ST_IDE: begin
                        crc_enable  <= 1'b1;
                        bit_counter <= 10'd0;
                        state       <= ST_FDF;
                    end

                    ST_FDF: begin
                        crc_enable <= 1'b1;
                        // FDF must be 1 for CAN-FD
                        if (destuffed_bit == 1'b1) begin
                            state <= ST_RES;
                        end else begin
                            // Classical CAN frame (or protocol anomaly)
                            state <= ST_DLC;
                        end
                    end

                    ST_RES: begin
                        crc_enable <= 1'b1;
                        state      <= ST_BRS;
                    end

                    ST_BRS: begin
                        crc_enable <= 1'b1;
                        brs_latch  <= destuffed_bit;
                        if (destuffed_bit == 1'b1) begin
                            data_rate_active <= 1'b1; // Switch to fast data baud rate
                        end
                        state <= ST_ESI;
                    end

                    ST_ESI: begin
                        crc_enable  <= 1'b1;
                        bit_counter <= 10'd0;
                        frame_dlc   <= 4'd0;
                        state       <= ST_DLC;
                    end

                    ST_DLC: begin
                        crc_enable <= 1'b1;
                        frame_dlc  <= {frame_dlc[2:0], destuffed_bit};
                        if (bit_counter == 10'd3) begin
                            bit_counter       <= 10'd0;
                            payload_len_bytes <= dlc_to_bytes({frame_dlc[2:0], destuffed_bit});
                            if (dlc_to_bytes({frame_dlc[2:0], destuffed_bit}) == 7'd0) begin
                                stuffing_mode <= 2'b10; // Fixed stuffing for CRC
                                state         <= ST_STUFF_CNT;
                            end else begin
                                state <= ST_DATA;
                            end
                        end else begin
                            bit_counter <= bit_counter + 1'b1;
                        end
                    end

                    ST_DATA: begin
                        crc_enable   <= 1'b1;
                        payload_data <= {payload_data[510:0], destuffed_bit};
                        if (bit_counter == ((payload_len_bytes * 10'd8) - 1'b1)) begin
                            bit_counter   <= 10'd0;
                            stuffing_mode <= 2'b10; // Switch to fixed stuffing for CRC
                            state         <= ST_STUFF_CNT;
                        end else begin
                            bit_counter <= bit_counter + 1'b1;
                        end
                    end

                    ST_STUFF_CNT: begin
                        crc_enable    <= 1'b1;
                        stuff_cnt_reg <= {stuff_cnt_reg[2:0], destuffed_bit};
                        if (bit_counter == 10'd3) begin
                            bit_counter <= 10'd0;
                            crc_shift   <= 21'd0;
                            state       <= ST_CRC;
                        end else begin
                            bit_counter <= bit_counter + 1'b1;
                        end
                    end

                    ST_CRC: begin
                        crc_shift <= {crc_shift[19:0], destuffed_bit};
                        if (use_crc21) begin
                            if (bit_counter == 10'd20) begin
                                crc_check_pulse <= 1'b1;
                                stuffing_mode   <= 2'b00; // No stuffing in delim/ACK
                                bit_counter     <= 10'd0;
                                state           <= ST_CRC_DELIM;
                            end else begin
                                bit_counter <= bit_counter + 1'b1;
                            end
                        end else begin
                            if (bit_counter == 10'd16) begin
                                crc_check_pulse <= 1'b1;
                                stuffing_mode   <= 2'b00;
                                bit_counter     <= 10'd0;
                                state           <= ST_CRC_DELIM;
                            end else begin
                                bit_counter <= bit_counter + 1'b1;
                            end
                        end
                    end

                    ST_CRC_DELIM: begin
                        data_rate_active <= 1'b0; // Switch back to nominal 500k rate
                        if (crc_error) begin
                            protocol_error_pulse <= 1'b1;
                            state                <= ST_ERROR_TRAP;
                        end else begin
                            state <= ST_ACK;
                        end
                    end

                    ST_ACK: begin
                        state <= ST_ACK_DELIM;
                    end

                    ST_ACK_DELIM: begin
                        bit_counter <= 10'd0;
                        state       <= ST_EOF;
                    end

                    ST_EOF: begin
                        if (bit_counter == 10'd6) begin
                            // Successful frame receipt
                            frame_valid_pulse <= 1'b1;
                            bus_idle          <= 1'b1;
                            state             <= ST_IDLE;
                        end else begin
                            bit_counter <= bit_counter + 1'b1;
                        end
                    end

                    ST_ERROR_TRAP: begin
                        // Await 11 consecutive recessive bits to re-enter bus idle
                        if (destuffed_bit == 1'b1) begin
                            if (bit_counter >= 10'd10) begin
                                bus_idle <= 1'b1;
                                state    <= ST_IDLE;
                            end else begin
                                bit_counter <= bit_counter + 1'b1;
                            end
                        end else begin
                            bit_counter <= 10'd0;
                        end
                    end

                    default: state <= ST_IDLE;
                endcase
            end
        end
    end

endmodule
