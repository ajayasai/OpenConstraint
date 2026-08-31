create_clock -name scan_clk -period 50 -waveform {0 25} [get_ports scan_clk]
set_input_delay  -clock scan_clk 5.0 [get_ports {clk rst_n scan_en din[0] din[1]}]
set_output_delay -clock scan_clk 5.0 [get_ports {dout[0] dout[1]}]
