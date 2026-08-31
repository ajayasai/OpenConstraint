create_clock -name core_clk -period 10 -waveform {0 4} [get_ports clk]
set_input_delay 2.0 -clock [get_clocks core_clk] -add_delay [get_ports data]
set_output_delay 2.0 -clock [get_clocks core_clk] -add_delay [get_ports q]
