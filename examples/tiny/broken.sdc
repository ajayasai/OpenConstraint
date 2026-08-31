# Deliberately broken: every line below exists to exercise an auditor rule.
create_clock -name ghost_clock [get_ports missing_clk]
create_clock -name all_ports -period 8 [get_ports *]
create_generated_clock -name divided -divide_by 2 \
  -source [get_pins u_missing/CLK] [get_pins u_ff0/Q]
set_false_path -from [get_ports *] -to [get_pins */D]
set_multicycle_path 2 -from [get_ports *] -to [get_pins */D]
