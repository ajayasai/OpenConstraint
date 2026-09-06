# MODE is an explicit caller-supplied value, never an environment variable.
source clock_helpers.sdc
if {$MODE eq "functional"} {
    set period 10
} elseif {$MODE eq "slow"} {
    set period 20
} else {
    # Unknown modes are deliberately rejected (error is not a modeled command).
    error {unsupported MODE}
}
make_clock core_clk clk $period
set delay [expr {$period / 5.0}]
foreach port {scan_clk rst_n scan_en din[0] din[1]} {
    set_input_delay -clock core_clk $delay [get_ports $port]
}
foreach port {dout[0] dout[1]} {
    set_output_delay -clock core_clk $delay [get_ports $port]
}
