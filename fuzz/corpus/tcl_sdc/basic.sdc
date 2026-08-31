create_clock -name core -period 10 -waveform {0 5} [get_ports clk]
set_input_delay 1.2 -clock core [get_ports {data[0] data[1]}]
set_output_delay 0.8 -clock core [all_outputs]
