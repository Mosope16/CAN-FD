## ============================================================================
## Timing and Pin Constraints for CAN-FD IDS Top Level
## Target: Xilinx Artix-7 (xc7a35tcsg324-1)
## Board Reference: Digilent Arty A7-35T / Nexys 4 DDR
## Clock: 100.000 MHz (10.000 ns Period)
## ============================================================================

# Primary 100 MHz System Clock
set_property -dict { PACKAGE_PIN E3 IOSTANDARD LVCMOS33 } [get_ports { clk }];
create_clock -period 10.000 -name sys_clk_pin -waveform {0.000 5.000} -add [get_ports { clk }];

# Asynchronous Reset (Active-Low Pushbutton CPU_RESET)
set_property -dict { PACKAGE_PIN C2 IOSTANDARD LVCMOS33 } [get_ports { rst_n }];

# Physical CAN-FD Transceiver RX Pin (PMOD Header JA - Pin 1)
set_property -dict { PACKAGE_PIN G13 IOSTANDARD LVCMOS33 } [get_ports { can_rx }];

# Alert Flag LEDs (Active-High)
set_property -dict { PACKAGE_PIN H5  IOSTANDARD LVCMOS33 } [get_ports { alert_valid }];          # LED0
set_property -dict { PACKAGE_PIN J5  IOSTANDARD LVCMOS33 } [get_ports { alert_dos }];            # LED1
set_property -dict { PACKAGE_PIN T9  IOSTANDARD LVCMOS33 } [get_ports { alert_fuzzing }];        # LED2
set_property -dict { PACKAGE_PIN T10 IOSTANDARD LVCMOS33 } [get_ports { alert_spoofing }];       # LED3
set_property -dict { PACKAGE_PIN E1  IOSTANDARD LVCMOS33 } [get_ports { alert_replay }];         # RGB0_B
set_property -dict { PACKAGE_PIN G6  IOSTANDARD LVCMOS33 } [get_ports { alert_suppression }];    # RGB0_R
set_property -dict { PACKAGE_PIN G3  IOSTANDARD LVCMOS33 } [get_ports { alert_protocol_error }]; # RGB1_R

# Status & Classification Bits (PMOD Header JB)
set_property -dict { PACKAGE_PIN D14 IOSTANDARD LVCMOS33 } [get_ports { detected_class[0] }];
set_property -dict { PACKAGE_PIN F16 IOSTANDARD LVCMOS33 } [get_ports { detected_class[1] }];
set_property -dict { PACKAGE_PIN G16 IOSTANDARD LVCMOS33 } [get_ports { detected_class[2] }];

# Timing Budget & I/O Delays
set_input_delay -clock [get_clocks sys_clk_pin] -min 1.000 [get_ports { can_rx rst_n }];
set_input_delay -clock [get_clocks sys_clk_pin] -max 3.500 [get_ports { can_rx rst_n }];

set_output_delay -clock [get_clocks sys_clk_pin] -min 0.500 [get_ports { alert_* detected_class* }];
set_output_delay -clock [get_clocks sys_clk_pin] -max 2.500 [get_ports { alert_* detected_class* }];

# Set false path on asynchronous reset release
set_false_path -from [get_ports rst_n]
