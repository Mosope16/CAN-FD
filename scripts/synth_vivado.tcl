# ==============================================================================
# Vivado Batch Non-Project Synthesis & Implementation Script
# Target FPGA: Xilinx Artix-7 xc7a35tcsg324-1
# Project: CAN-FD Bit-Stream Monitor and Decision-Tree IDS Unit
# ==============================================================================

set PROJECT_ROOT [file normalize [file join [file dirname [info script]] ".."]]
set OUTPUT_DIR   [file join $PROJECT_ROOT "results" "reports"]

file mkdir $OUTPUT_DIR

puts "=================================================================="
puts "Starting CAN-FD IDS Artix-7 Synthesis and Implementation..."
puts "Target Part: xc7a35tcsg324-1"
puts "Project Root: $PROJECT_ROOT"
puts "=================================================================="

# 1. Read Design Sources
set_param general.maxThreads 4

read_verilog -sv [file join $PROJECT_ROOT "rtl" "canfd_pkg.vh"]
read_verilog [glob [file join $PROJECT_ROOT "rtl" "*.v"]]
read_xdc [file join $PROJECT_ROOT "rtl" "canfd_ids.xdc"]

# 2. Synthesis
puts "\n--> Running synth_design (top: canfd_ids_top)..."
synth_design -top canfd_ids_top -part xc7a35tcsg324-1 -directive AreaOptimized_high

# 3. Optimization and Placement
puts "\n--> Running opt_design and place_design..."
opt_design
place_design -directive Explore

# 4. Routing
puts "\n--> Running route_design..."
route_design -directive Explore

# 5. Generate Evidence Reports
puts "\n--> Writing Implementation Reports..."
report_utilization -hierarchical -file [file join $OUTPUT_DIR "post_route_utilization.rpt"]
report_timing_summary -delay_type min_max -report_unconstrained -check_timing_verbose -max_paths 10 -file [file join $OUTPUT_DIR "post_route_timing.rpt"]
report_power -file [file join $OUTPUT_DIR "post_route_power.rpt"]
report_drc -file [file join $OUTPUT_DIR "post_route_drc.rpt"]

puts "\n=================================================================="
puts "Synthesis and Place & Route Complete!"
puts "Utilization Report : $OUTPUT_DIR/post_route_utilization.rpt"
puts "Timing Report      : $OUTPUT_DIR/post_route_timing.rpt"
puts "=================================================================="
