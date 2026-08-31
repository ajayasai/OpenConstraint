create_clock -name core_clk -period 10 -waveform {0 5} [get_ports clk]
set_input_delay  -clock core_clk 2.0 [get_ports {scan_clk rst_n scan_en din[0] din[1]}]
set_output_delay -clock core_clk 2.0 [get_ports {dout[0] dout[1]}]
