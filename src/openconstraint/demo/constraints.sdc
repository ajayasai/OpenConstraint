create_clock -name core_clk -period 10 -waveform {0 5} [get_ports clk]
set_input_delay  -clock core_clk 2.0 [get_ports {rst_n din[0] din[1] scan_clk scan_en}]
set_output_delay -clock core_clk 2.0 [get_ports {dout[0] dout[1]}]
