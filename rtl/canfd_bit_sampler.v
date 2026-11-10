// ============================================================================
// CAN-FD Dual-Rate Bit Timing and Sampler
// Supports 500 kbps Nominal Phase (80% SP) and 2.0 Mbps Data Phase (70% SP)
// Driven by 100 MHz System Clock (t_q = 10.0 ns).
// ============================================================================

`timescale 1ns / 1ps
`include "canfd_pkg.vh"

module canfd_bit_sampler (
    input  wire       clk,
    input  wire       rst_n,
    input  wire       rx_sync,
    input  wire       falling_edge,
    input  wire       data_rate_active,  // 0: Nominal (500k), 1: Fast (2M)
    input  wire       bus_idle,          // 1: Bus is currently idle (awaiting SOF)
    output reg        sample_point_pulse,// 1-cycle strobe at exact sample point
    output reg        bit_sample,        // Latched bit level at sample point
    output reg        bit_end_pulse      // 1-cycle strobe at end of bit time
);

    reg [7:0] cycle_cnt;
    wire [7:0] bit_total_cycles;
    wire [7:0] sample_cycle;

    assign bit_total_cycles = data_rate_active ? `DATA_BIT_CYCLES : `NOMINAL_BIT_CYCLES;
    assign sample_cycle     = data_rate_active ? `DATA_SAMPLE_CYCLE : `NOMINAL_SAMPLE_CYCLE;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            cycle_cnt          <= 8'd0;
            sample_point_pulse <= 1'b0;
            bit_sample         <= 1'b1;
            bit_end_pulse      <= 1'b0;
        end else begin
            sample_point_pulse <= 1'b0;
            bit_end_pulse      <= 1'b0;

            if (bus_idle && falling_edge) begin
                // Hard Synchronization on SOF edge
                cycle_cnt <= 8'd1; // First cycle of dominant SOF
            end else begin
                if (cycle_cnt == sample_cycle) begin
                    sample_point_pulse <= 1'b1;
                    bit_sample         <= rx_sync;
                end

                if (cycle_cnt >= (bit_total_cycles - 1'b1)) begin
                    cycle_cnt     <= 8'd0;
                    bit_end_pulse <= 1'b1;
                end else begin
                    cycle_cnt <= cycle_cnt + 1'b1;
                end
            end
        end
    end

endmodule
