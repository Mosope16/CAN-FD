# Vivado Setup on Windows

## 1. Install Vivado

Install AMD/Xilinx Vivado ML 2022.2 or newer and select:

- Vivado Design Suite
- Artix-7 device support
- Vivado Tcl shell and batch tools

The project target is `xc7a35tcsg324-1`.

## 2. Verify the RTL

From PowerShell, if Verilator is installed:

```powershell
verilator --lint-only -Wall -Wno-DECLFILENAME -Irtl rtl\canfd_ids_top.v
```

This check is optional; Vivado synthesis is the authoritative HDL build check.

## 3. Run the Vivado batch flow

Use forward slashes inside Vivado Tcl even on Windows:

```tcl
cd C:/Users/<user>/Projects/CAN-FD
source scripts/synth_vivado.tcl
```

The script reads all Verilog files under `rtl/`, loads `rtl/canfd_ids.xdc`, synthesizes `canfd_ids_top`, places and routes it, and writes:

- `results/reports/post_route_utilization.rpt`
- `results/reports/post_route_timing.rpt`
- `results/reports/post_route_power.rpt`
- `results/reports/post_route_drc.rpt`
- `results/reports/canfd_ids.bit`

From Command Prompt, the equivalent is:

```bat
"C:\Xilinx\Vivado\2022.2\bin\vivado.bat" -mode batch -source scripts\synth_vivado.tcl
```

If Vivado was installed elsewhere, change only the path to `vivado.bat`.

## 4. Board constraints

The supplied XDC contains Artix-7 constraints and a 100 MHz clock, but physical pin assignments are board-specific. Obtain the master XDC for the exact board and update `rtl/canfd_ids.xdc` before generating a hardware bitstream.

Do not use the current pins blindly: the comments mention both Arty A7-35T and Nexys 4 DDR, which have different pinouts.

## 5. Program the board

After a successful run, open Vivado Hardware Manager, connect to the target, select `results/reports/canfd_ids.bit`, and program the device. A CAN-FD transceiver is required; connect the transceiver RX output to `can_rx` at the assigned FPGA pin. Do not connect CAN bus wires directly to an FPGA I/O pin.