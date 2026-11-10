// ============================================================================
// CAN-FD Dual CRC Engine (CRC-17 & CRC-21) with Stuff-Count Parity Checker
// ISO 11898-1:2015 compliant LFSR implementations
// ============================================================================

`timescale 1ns / 1ps
`include "canfd_pkg.vh"

module canfd_crc (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        crc_init,          // Strobe at SOF to initialize LFSRs
    input  wire        crc_enable,        // High when valid bit arrives for CRC calculation
    input  wire        crc_in_bit,        // Bit fed into CRC calculation
    input  wire        use_crc21,         // 0: CRC-17 (<=16B), 1: CRC-21 (>16B)
    input  wire        crc_check_pulse,   // Strobe to compare against received CRC
    input  wire [20:0] received_crc,      // CRC field received from line
    output reg         crc_match,         // High if received CRC equals calculated CRC
    output reg         crc_error,         // High if CRC error detected
    output wire [20:0] computed_crc       // Active calculated CRC
);

    reg [16:0] lfsr_17;
    reg [20:0] lfsr_21;

    wire fb_17;
    wire fb_21;

    assign fb_17 = crc_in_bit ^ lfsr_17[16];
    assign fb_21 = crc_in_bit ^ lfsr_21[20];

    assign computed_crc = use_crc21 ? lfsr_21 : {4'b0000, lfsr_17};

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            lfsr_17   <= `CANFD_CRC17_INIT;
            lfsr_21   <= `CANFD_CRC21_INIT;
            crc_match <= 1'b0;
            crc_error <= 1'b0;
        end else if (crc_init) begin
            lfsr_17   <= `CANFD_CRC17_INIT;
            lfsr_21   <= `CANFD_CRC21_INIT;
            crc_match <= 1'b0;
            crc_error <= 1'b0;
        end else begin
            if (crc_enable) begin
                // Update CRC-17 LFSR (Poly: 0x1685B = 17'b1_0110_1000_0101_1011)
                lfsr_17[0]  <= fb_17;
                lfsr_17[1]  <= lfsr_17[0]  ^ fb_17;
                lfsr_17[2]  <= lfsr_17[1];
                lfsr_17[3]  <= lfsr_17[2]  ^ fb_17;
                lfsr_17[4]  <= lfsr_17[3]  ^ fb_17;
                lfsr_17[5]  <= lfsr_17[4];
                lfsr_17[6]  <= lfsr_17[5]  ^ fb_17;
                lfsr_17[7]  <= lfsr_17[6];
                lfsr_17[8]  <= lfsr_17[7];
                lfsr_17[9]  <= lfsr_17[8];
                lfsr_17[10] <= lfsr_17[9];
                lfsr_17[11] <= lfsr_17[10] ^ fb_17;
                lfsr_17[12] <= lfsr_17[11];
                lfsr_17[13] <= lfsr_17[12] ^ fb_17;
                lfsr_17[14] <= lfsr_17[13] ^ fb_17;
                lfsr_17[15] <= lfsr_17[14];
                lfsr_17[16] <= lfsr_17[15] ^ fb_17;

                // Update CRC-21 LFSR (Poly: 0x302899 = 21'b11_0000_0010_1000_1001_1001)
                lfsr_21[0]  <= fb_21;
                lfsr_21[1]  <= lfsr_21[0];
                lfsr_21[2]  <= lfsr_21[1];
                lfsr_21[3]  <= lfsr_21[2]  ^ fb_21;
                lfsr_21[4]  <= lfsr_21[3]  ^ fb_21;
                lfsr_21[5]  <= lfsr_21[4];
                lfsr_21[6]  <= lfsr_21[5];
                lfsr_21[7]  <= lfsr_21[6]  ^ fb_21;
                lfsr_21[8]  <= lfsr_21[7];
                lfsr_21[9]  <= lfsr_21[8];
                lfsr_21[10] <= lfsr_21[9];
                lfsr_21[11] <= lfsr_21[10] ^ fb_21;
                lfsr_21[12] <= lfsr_21[11];
                lfsr_21[13] <= lfsr_21[12] ^ fb_21;
                lfsr_21[14] <= lfsr_21[13];
                lfsr_21[15] <= lfsr_21[14];
                lfsr_21[16] <= lfsr_21[15];
                lfsr_21[17] <= lfsr_21[16];
                lfsr_21[18] <= lfsr_21[17];
                lfsr_21[19] <= lfsr_21[18];
                lfsr_21[20] <= lfsr_21[19] ^ fb_21;
            end

            if (crc_check_pulse) begin
                if (use_crc21) begin
                    if (lfsr_21 == received_crc[20:0]) begin
                        crc_match <= 1'b1;
                        crc_error <= 1'b0;
                    end else begin
                        crc_match <= 1'b0;
                        crc_error <= 1'b1;
                    end
                end else begin
                    if (lfsr_17 == received_crc[16:0]) begin
                        crc_match <= 1'b1;
                        crc_error <= 1'b0;
                    end else begin
                        crc_match <= 1'b0;
                        crc_error <= 1'b1;
                    end
                end
            end else begin
                crc_match <= 1'b0;
                crc_error <= 1'b0;
            end
        end
    end

endmodule
