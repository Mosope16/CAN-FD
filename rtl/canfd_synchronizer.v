// ============================================================================
// CAN-FD Physical Line Synchronizer and Glitch Filter
// Resolves metastability from asynchronous transceiver RX and filters glitches.
// ============================================================================

`timescale 1ns / 1ps

module canfd_synchronizer (
    input  wire clk,            // 100 MHz system clock
    input  wire rst_n,          // Active-low synchronous reset
    input  wire can_rx_async,   // Asynchronous RX from CAN transceiver
    output reg  rx_sync,        // Synchronized and filtered output
    output wire falling_edge,   // Recessive-to-dominant edge (hard resync)
    output wire rising_edge     // Dominant-to-recessive edge
);

    // 2-Stage Synchronizer Flops
    reg sync_ff1;
    reg sync_ff2;
    reg sync_ff3;
    reg rx_prev;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            sync_ff1 <= 1'b1; // Idle CAN bus is recessive (logic 1)
            sync_ff2 <= 1'b1;
            sync_ff3 <= 1'b1;
            rx_sync  <= 1'b1;
            rx_prev  <= 1'b1;
        end else begin
            sync_ff1 <= can_rx_async;
            sync_ff2 <= sync_ff1;
            sync_ff3 <= sync_ff2;

            // 3-sample Majority Filter: protects against transient sub-cycle spikes
            if ((sync_ff1 & sync_ff2) | (sync_ff2 & sync_ff3) | (sync_ff1 & sync_ff3)) begin
                rx_sync <= 1'b1;
            end else begin
                rx_sync <= 1'b0;
            end

            rx_prev <= rx_sync;
        end
    end

    // Edge Detections
    assign falling_edge = (rx_prev == 1'b1) && (rx_sync == 1'b0);
    assign rising_edge  = (rx_prev == 1'b0) && (rx_sync == 1'b1);

endmodule
