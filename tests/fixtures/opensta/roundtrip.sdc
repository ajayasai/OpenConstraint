create_clock -name core_clk -period 10 [get_ports clk]
create_clock -name phase_clk -period 8 -waveform {1 3}
set_input_delay 2.0 -clock [get_clocks core_clk] -add_delay [get_ports data]
set_output_delay 2.0 -clock [get_clocks core_clk] -add_delay [get_ports q]
