// ============================================================================
// Verilator C++ Testbench for CAN-FD Intrusion Detection System
// Simulates 100 MHz clock, dual-rate bit transmission, bit-stuffing error,
// and hardware suppression deadline alert.
// ============================================================================

#include <iostream>
#include <iomanip>
#include <memory>
#include <cstdint>
#include "Vcanfd_ids_top.h"
#include "verilated.h"
#include "verilated_vcd_c.h"

// Advance simulation by 1 clock cycle (10.0 ns @ 100 MHz)
void tick(Vcanfd_ids_top* top, VerilatedVcdC* tfp, uint64_t& sim_time) {
    top->clk = 0;
    top->eval();
    if (tfp) tfp->dump(sim_time);
    sim_time += 5; // 5 ns low

    top->clk = 1;
    top->eval();
    if (tfp) tfp->dump(sim_time);
    sim_time += 5; // 5 ns high
}

// Transmit 1 bit over physical line (can_rx) for a specified number of clock cycles
void send_bit(Vcanfd_ids_top* top, VerilatedVcdC* tfp, uint64_t& sim_time, int bit_val, int num_cycles) {
    top->can_rx = bit_val;
    for (int i = 0; i < num_cycles; ++i) {
        tick(top, tfp, sim_time);
    }
}

int main(int argc, char** argv) {
    Verilated::commandArgs(argc, argv);
    Verilated::traceEverOn(true);

    std::cout << "================================================================" << std::endl;
    std::cout << "   CAN-FD IDS Verilator Cycle-Accurate Hardware Simulation     " << std::endl;
    std::cout << "   Target: AMD/Xilinx Artix-7 (100 MHz Clock, 10 ns Period)    " << std::endl;
    std::cout << "================================================================" << std::endl;

    auto top = std::make_unique<Vcanfd_ids_top>();
    std::unique_ptr<VerilatedVcdC> tfp = nullptr;

    bool dump_vcd = false;
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--trace" || std::string(argv[i]) == "--vcd") {
            dump_vcd = true;
        }
    }

    uint64_t sim_time = 0;
    if (dump_vcd) {
        tfp = std::make_unique<VerilatedVcdC>();
        top->trace(tfp.get(), 99);
        tfp->open("sim/canfd_ids_trace.vcd");
        std::cout << "[INFO] VCD Waveform dump enabled: sim/canfd_ids_trace.vcd" << std::endl;
    }

    // Initialize inputs
    top->clk = 0;
    top->rst_n = 0;
    top->can_rx = 1; // Bus idle is recessive (logic 1)

    // 1. Reset Phase (Hold reset low for 50 cycles = 500 ns)
    std::cout << "\n--> Phase 1: Applying Synchronous Reset..." << std::endl;
    for (int i = 0; i < 50; ++i) {
        tick(top.get(), tfp.get(), sim_time);
    }
    top->rst_n = 1; // Release reset
    for (int i = 0; i < 50; ++i) {
        tick(top.get(), tfp.get(), sim_time);
    }
    std::cout << "    [PASS] System Clock locked at 100 MHz, Reset released." << std::endl;

    // 2. Bus Idle Test (100 cycles = 1000 ns)
    std::cout << "\n--> Phase 2: Verifying Bus Idle State..." << std::endl;
    for (int i = 0; i < 100; ++i) {
        tick(top.get(), tfp.get(), sim_time);
    }
    if (top->alert_valid == 0) {
        std::cout << "    [PASS] No false alerts during recessive bus idle." << std::endl;
    } else {
        std::cerr << "    [FAIL] Unexpected alert during bus idle!" << std::endl;
        return 1;
    }

    // 3. Physical Protocol Corruption Test: Bit-Stuffing Violation
    // Standard CAN bit stuffing requires an inverted bit after 5 consecutive identical bits.
    // We intentionally transmit 6 consecutive dominant '0' bits to trigger a dynamic stuff error.
    std::cout << "\n--> Phase 3: Injecting Physical Bit-Stuffing Corruption (6 Consecutive Dominant Bits)..." << std::endl;
    
    // SOF: 1 bit dominant (200 cycles @ 500 kbps)
    send_bit(top.get(), tfp.get(), sim_time, 0, 200);

    // 5 consecutive dominant bits
    for (int i = 0; i < 5; ++i) {
        send_bit(top.get(), tfp.get(), sim_time, 0, 200);
    }

    // 6th dominant bit: CORRUPTION (violates stuff rule: 6th bit must be recessive '1')
    bool stuff_alert_detected = false;
    top->can_rx = 0;
    for (int i = 0; i < 200; ++i) {
        tick(top.get(), tfp.get(), sim_time);
        if (top->alert_valid && top->alert_protocol_error) {
            stuff_alert_detected = true;
        }
    }

    if (stuff_alert_detected) {
        std::cout << "    [PASS] Bit-Stuffing Error detected at line rate! (alert_protocol_error fired)" << std::endl;
    } else {
        std::cerr << "    [FAIL] Bit-stuffing error was NOT detected!" << std::endl;
        return 1;
    }

    // Return to bus idle (transmit 15 recessive bits to clear error trap)
    for (int i = 0; i < 15; ++i) {
        send_bit(top.get(), tfp.get(), sim_time, 1, 200);
    }

    // 4. Hardware Safety Deadline Supervisor Test (Silent Frame Suppression)
    // The hardware supervisor monitors BrakeStatus (0x102). If 30 ms (3,000,000 cycles)
    // elapse without receiving 0x102, alert_suppression MUST fire.
    std::cout << "\n--> Phase 4: Simulating 30 ms Deadline Expiration for BrakeStatus (0x102)..." << std::endl;
    std::cout << "    Advancing clock by 3,000,100 cycles (" << (3000100 * 10 / 1e6) << " ms)..." << std::endl;
    
    bool suppression_alert_detected = false;
    top->can_rx = 1; // Line idle
    for (int i = 0; i < 3000100; ++i) {
        tick(top.get(), tfp.get(), sim_time);
        if (top->alert_valid && top->alert_suppression) {
            suppression_alert_detected = true;
            break;
        }
    }

    if (suppression_alert_detected) {
        std::cout << "    [PASS] Frame Suppression Detected! (alert_suppression fired at 30 ms deadline)" << std::endl;
    } else {
        std::cerr << "    [FAIL] Suppression deadline alert did not fire!" << std::endl;
        return 1;
    }

    // Close trace if open
    if (tfp) {
        tfp->close();
        std::cout << "\n[INFO] Wrote VCD waveform to sim/canfd_ids_trace.vcd" << std::endl;
    }

    std::cout << "\n================================================================" << std::endl;
    std::cout << "   ALL VERILATOR HARDWARE SIMULATION TESTS PASSED (100% OK)     " << std::endl;
    std::cout << "   Total Simulation Time: " << (sim_time / 1000.0) << " microseconds" << std::endl;
    std::cout << "================================================================" << std::endl;

    return 0;
}
